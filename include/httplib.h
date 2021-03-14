//
// Copyright (c) 2020 Yuji Hirose, 2021 Russell Trahan. All rights reserved. 
// Portions of this project have been copied from cpp-httplib by Yuji Hirose and modified by Russell Trahan.
//  
// MIT License
//

#pragma once

#ifdef CPPHTTPLIBMAKEDLL
	#if defined(_MSC_VER)
		#define CPPHTTPLIBEXPORT __declspec(dllexport)
	#elif defined(__GNUC__)
		#define CPPHTTPLIBEXPORT __attribute__((visibility("default")))
		#define __cdecl
	#endif
#else
	#if defined(_MSC_VER)
		#define CPPHTTPLIBEXPORT __declspec(dllimport)
	#elif defined(__GNUC__)
		#define CPPHTTPLIBEXPORT __attribute__((visibility("default")))
		#define __cdecl
	#endif
#endif

#ifdef _WIN32
#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif //_CRT_SECURE_NO_WARNINGS

#ifndef _CRT_NONSTDC_NO_DEPRECATE
#define _CRT_NONSTDC_NO_DEPRECATE
#endif //_CRT_NONSTDC_NO_DEPRECATE

#include <stdint.h>

#if defined(_MSC_VER)
#ifdef _WIN64
using ssize_t = int64_t;
#else
using ssize_t = int32_t;
#endif

#if _MSC_VER < 1900
#define snprintf _snprintf_s
#endif
#endif // _MSC_VER

#ifndef S_ISREG
#define S_ISREG(m) (((m)&S_IFREG) == S_IFREG)
#endif // S_ISREG

#ifndef S_ISDIR
#define S_ISDIR(m) (((m)&S_IFDIR) == S_IFDIR)
#endif // S_ISDIR

#ifndef NOMINMAX
#define NOMINMAX
#endif // NOMINMAX

#include <io.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#ifndef WSA_FLAG_NO_HANDLE_INHERIT
#define WSA_FLAG_NO_HANDLE_INHERIT 0x80
#endif

#ifdef _MSC_VER
#pragma comment(lib, "ws2_32.lib")
#endif

#ifndef strcasecmp
#define strcasecmp _stricmp
#endif // strcasecmp

using socket_t = SOCKET;
#ifdef CPPHTTPLIB_USE_POLL
#define poll(fds, nfds, timeout) WSAPoll(fds, nfds, timeout)
#endif

#else // not _WIN32

#include <arpa/inet.h>
#include <cstring>
#include <ifaddrs.h>
#include <netdb.h>
#include <netinet/in.h>
#ifdef CPPHTTPLIB_USE_POLL
#include <poll.h>
#endif
#include <csignal>
#include <pthread.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

using socket_t = int;
#define INVALID_SOCKET (-1)
#endif //_WIN32

#include <array>
#include <atomic>
#include <cassert>
#include <chrono>
#include <climits>
#include <condition_variable>
#include <errno.h>
#include <fcntl.h>
#include <fstream>
#include <functional>
#include <list>
#include <map>
#include <memory>
#include <mutex>
#include <random>
#include <regex>
#include <string>
#include <sys/stat.h>
#include <thread>

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
#include <openssl/err.h>
#include <openssl/md5.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include <iomanip>
#include <iostream>
#include <sstream>

// #if OPENSSL_VERSION_NUMBER < 0x1010100fL
// #error Sorry, OpenSSL versions prior to 1.1.1 are not supported
// #endif

#if OPENSSL_VERSION_NUMBER < 0x10100000L
#include <openssl/crypto.h>
inline const unsigned char* ASN1_STRING_get0_data(const ASN1_STRING* asn1)
{
	return M_ASN1_STRING_data(asn1);
}
#endif
#endif

#ifdef CPPHTTPLIB_ZLIB_SUPPORT
#include <zlib.h>
#endif

/*
 * Declaration
 */
namespace httplib
{
	using namespace std::chrono_literals;

	namespace detail
	{
		struct ci
		{
			CPPHTTPLIBEXPORT bool operator()(const std::string& s1, const std::string& s2) const;
		};
	}

	using Headers = std::multimap<std::string, std::string, detail::ci>;

	using Params = std::multimap<std::string, std::string>;
	using Match = std::smatch;

	using Progress = std::function<bool(uint64_t current, uint64_t total)>;

	struct MultipartFormData
	{
		std::string name;
		std::string content;
		std::string filename;
		std::string content_type;
	};
	using MultipartFormDataItems = std::vector<MultipartFormData>;
	using MultipartFormDataMap = std::multimap<std::string, MultipartFormData>;

	class DataSink
	{
	public:
		CPPHTTPLIBEXPORT DataSink();

		DataSink(const DataSink&) = delete;
		DataSink& operator=(const DataSink&) = delete;
		DataSink(DataSink&&) = delete;
		DataSink& operator=(DataSink&&) = delete;

		std::function<void(const char* data, size_t data_len)> write;
		std::function<void()> done;
		std::function<bool()> is_writable;
		std::ostream os;

	private:
		class data_sink_streambuf : public std::streambuf
		{
		public:
			CPPHTTPLIBEXPORT data_sink_streambuf(DataSink& sink);

		protected:
			CPPHTTPLIBEXPORT std::streamsize xsputn(const char* s, std::streamsize n);

		private:
			DataSink& sink_;
		};

		data_sink_streambuf sb_;
	};

	using ContentProvider = std::function<bool(size_t offset, size_t length, DataSink& sink)>;
	using ChunkedContentProvider = std::function<bool(size_t offset, DataSink& sink)>;
	using ContentReceiver = std::function<bool(const char* data, size_t data_length)>;
	using MultipartContentHeader = std::function<bool(const MultipartFormData& file)>;

	struct ChunkedContentCounters
	{
		size_t offset = 0;
		ssize_t total_written_length = 0;
		bool ok = true;
		bool data_available = true;
	};

	class ContentReader
	{
	public:
		using Reader = std::function<bool(ContentReceiver receiver)>;
		using MultipartReader = std::function<bool(MultipartContentHeader header, ContentReceiver receiver)>;

		CPPHTTPLIBEXPORT ContentReader(Reader reader, MultipartReader multipart_reader);

		CPPHTTPLIBEXPORT bool operator()(MultipartContentHeader header, ContentReceiver receiver) const;
		CPPHTTPLIBEXPORT bool operator()(ContentReceiver receiver) const;

		Reader reader_;
		MultipartReader multipart_reader_;
	};

	using Range = std::pair<ssize_t, ssize_t>;
	using Ranges = std::vector<Range>;

	struct Response
	{
		std::string version;
		int status = -1;
		Headers headers;
		std::string body;

		CPPHTTPLIBEXPORT bool has_header(const char* key) const;
		CPPHTTPLIBEXPORT std::string get_header_value(const char* key, size_t id = 0) const;
		CPPHTTPLIBEXPORT size_t get_header_value_count(const char* key) const;
		CPPHTTPLIBEXPORT void set_header(const char* key, const char* val);
		CPPHTTPLIBEXPORT void set_header(const char* key, const std::string& val);

		CPPHTTPLIBEXPORT void set_redirect(const char* url, int status = 302);
		CPPHTTPLIBEXPORT void set_content(const char* s, size_t n, const char* content_type);
		CPPHTTPLIBEXPORT void set_content(std::string s, const char* content_type);

		CPPHTTPLIBEXPORT void set_content_provider(size_t length, ContentProvider provider, std::function<void()> resource_releaser = [] {});

		CPPHTTPLIBEXPORT void set_chunked_content_provider(ChunkedContentProvider provider, std::function<void()> resource_releaser = [] {});

		Response() = default;
		Response(const Response&) = default;
		Response& operator=(const Response&) = default;
		Response(Response&&) = default;
		Response& operator=(Response&&) = default;
		CPPHTTPLIBEXPORT ~Response();

		// private members...
		size_t content_length_ = 0;
		ContentProvider content_provider_;
		std::function<void()> content_provider_resource_releaser_;
	};

	using ResponseHandler = std::function<bool(const Response& response)>;

	struct Request
	{
		std::string method;
		std::string path;
		Headers headers;
		std::string body;

		std::string remote_addr;
		int remote_port = -1;

		// for server
		std::string version;
		std::string target;
		Params params;
		MultipartFormDataMap files;
		Ranges ranges;
		Match matches;

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
		const SSL* ssl = nullptr;
#endif

		CPPHTTPLIBEXPORT bool has_header(const char *key) const;
		CPPHTTPLIBEXPORT std::string get_header_value(const char* key, size_t id = 0) const;
		CPPHTTPLIBEXPORT size_t get_header_value_count(const char* key) const;
		CPPHTTPLIBEXPORT void set_header(const char* key, const char* val);
		CPPHTTPLIBEXPORT void set_header(const char* key, const std::string& val);

		CPPHTTPLIBEXPORT bool has_param(const char* key) const;
		CPPHTTPLIBEXPORT std::string get_param_value(const char* key, size_t id = 0) const;
		CPPHTTPLIBEXPORT size_t get_param_value_count(const char* key) const;

		CPPHTTPLIBEXPORT bool is_multipart_form_data() const;

		CPPHTTPLIBEXPORT bool has_file(const char* key) const;
		CPPHTTPLIBEXPORT MultipartFormData get_file_value(const char* key) const;

		// private members...
		size_t authorization_count_ = 0;
	};

	class Stream
	{
	public:
		virtual ~Stream() = default;

		virtual bool is_readable() const = 0;
		virtual bool is_writable() const = 0;

		virtual ssize_t read(char* ptr, size_t size) = 0;
		virtual ssize_t write(const char* ptr, size_t size) = 0;
		virtual void get_remote_ip_and_port(std::string& ip, int& port) const = 0;

		CPPHTTPLIBEXPORT ssize_t write(const char* ptr);
		CPPHTTPLIBEXPORT ssize_t write(const std::string& s);

		template <typename... Args>
		ssize_t write_format(const char* fmt, const Args &... args)
		{
			std::array<char, 2048> buf;

#if defined(_MSC_VER) && _MSC_VER < 1900
			auto sn = _snprintf_s(buf, bufsiz, buf.size() - 1, fmt, args...);
#else
			auto sn = snprintf(buf.data(), buf.size() - 1, fmt, args...);
#endif
			if (sn <= 0)
				return sn;

			auto n = static_cast<size_t>(sn);

			if (n >= buf.size() - 1)
			{
				std::vector<char> glowable_buf(buf.size());

				while (n >= glowable_buf.size() - 1)
				{
					glowable_buf.resize(glowable_buf.size() * 2);
#if defined(_MSC_VER) && _MSC_VER < 1900
					n = static_cast<size_t>(_snprintf_s(&glowable_buf[0], glowable_buf.size(), glowable_buf.size() - 1, fmt, args...));
#else
					n = static_cast<size_t>(snprintf(&glowable_buf[0], glowable_buf.size() - 1, fmt, args...));
#endif
				}
				return write(&glowable_buf[0], n);
			}
			else
				return write(buf.data(), n);
		}
	};

	class TaskQueue
	{
	public:
		TaskQueue() = default;
		virtual ~TaskQueue() = default;

		virtual void enqueue(std::function<void()> fn) = 0;
		virtual void shutdown() = 0;

		virtual void on_idle() {}
	};

	class ThreadPool : public TaskQueue {
	public:
		explicit ThreadPool(size_t n);

		ThreadPool() = delete;
		ThreadPool(const ThreadPool&) = delete;
		ThreadPool(ThreadPool&&) = delete;
		ThreadPool& operator=(const ThreadPool&) = delete;
		ThreadPool& operator=(ThreadPool&&) = delete;
		~ThreadPool() override = default;

		CPPHTTPLIBEXPORT void enqueue(std::function<void()> fn) override;

		CPPHTTPLIBEXPORT void shutdown() override;

	private:
		struct worker
		{
			explicit worker(ThreadPool& pool);

			void operator()();

			ThreadPool& pool_;
		};
		friend struct worker;

		std::vector<std::thread> threads_;
		std::list<std::function<void()>> jobs_;

		bool shutdown_ = false;

		std::condition_variable cond_;
		std::mutex mutex_;
	};

	using Logger = std::function<void(const Request&, const Response&)>;
}
