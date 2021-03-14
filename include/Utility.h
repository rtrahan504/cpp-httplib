//
// Copyright (c) 2020 Yuji Hirose, 2021 Russell Trahan. All rights reserved. 
// Portions of this project have been copied from cpp-httplib by Yuji Hirose and modified by Russell Trahan.
//  
// MIT License
//

#pragma once

#include "httplib.h"

namespace httplib
{
	namespace detail
	{
		bool is_hex(char c, int& v);

		bool from_hex_to_i(const std::string& s, size_t i, size_t cnt, int& val);

		std::string from_i_to_hex(size_t n);

		size_t to_utf8(int code, char* buff);

		// NOTE: This code came up with the following stackoverflow post:
		// https://stackoverflow.com/questions/180947/base64-decode-snippet-in-c
		std::string base64_encode(const std::string& in);

		bool is_file(const std::string& path);

		bool is_dir(const std::string& path);

		bool is_valid_path(const std::string& path);

		void read_file(const std::string& path, std::string& out);

		std::string file_extension(const std::string& path);

		template <class Fn> void split(const char* b, const char* e, char d, Fn fn)
		{
			int i = 0;
			int beg = 0;

			while (e ? (b + i != e) : (b[i] != '\0'))
			{
				if (b[i] == d)
				{
					fn(&b[beg], &b[i]);
					beg = i + 1;
				}
				i++;
			}

			if (i)
			{
				fn(&b[beg], &b[i]);
			}
		}

		// NOTE: until the read size reaches `fixed_buffer_size`, use `fixed_buffer`
		// to store data. The call can set memory on stack for performance.
		class stream_line_reader
		{
		public:
			stream_line_reader(Stream& strm, char* fixed_buffer, size_t fixed_buffer_size);

			const char* ptr() const;

			size_t size() const;

			bool end_with_crlf() const;

			bool getline();

		private:
			void append(char c);

			Stream& strm_;
			char* fixed_buffer_;
			const size_t fixed_buffer_size_;
			size_t fixed_buffer_used_size_ = 0;
			std::string glowable_buffer_;
		};

		int close_socket(socket_t sock);

		ssize_t select_read(socket_t sock, std::chrono::microseconds timeout);

		ssize_t select_write(socket_t sock, std::chrono::microseconds timeout);

		bool wait_until_socket_is_ready(socket_t sock, std::chrono::microseconds timeout);

		class SocketStream : public Stream
		{
		public:
			SocketStream(socket_t sock, std::chrono::microseconds readTimeout, std::chrono::microseconds writeTimeout);
			~SocketStream() override;

			bool is_readable() const override;
			bool is_writable() const override;
			ssize_t read(char* ptr, size_t size) override;
			ssize_t write(const char* ptr, size_t size) override;
			void get_remote_ip_and_port(std::string& ip, int& port) const override;

		private:
			socket_t sock_;
			std::chrono::microseconds m_ReadTimeout;
			std::chrono::microseconds m_WriteTimeout;
		};

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
		class SSLSocketStream : public Stream
		{
		public:
			SSLSocketStream(socket_t sock, SSL* ssl, std::chrono::microseconds readTimeout, std::chrono::microseconds writeTimeout);
			~SSLSocketStream() override;

			bool is_readable() const override;
			bool is_writable() const override;
			ssize_t read(char* ptr, size_t size) override;
			ssize_t write(const char* ptr, size_t size) override;
			void get_remote_ip_and_port(std::string& ip, int& port) const override;

		private:
			socket_t sock_;
			SSL* ssl_;
			std::chrono::microseconds m_ReadTimeout;
			std::chrono::microseconds m_WriteTimeout;
		};
#endif

		class BufferStream : public Stream
		{
		public:
			BufferStream() = default;
			~BufferStream() override = default;

			bool is_readable() const override;
			bool is_writable() const override;
			ssize_t read(char* ptr, size_t size) override;
			ssize_t write(const char* ptr, size_t size) override;
			void get_remote_ip_and_port(std::string& ip, int& port) const override;

			const std::string& get_buffer() const;

		private:
			std::string buffer;
			size_t position = 0;
		};

		int shutdown_socket(socket_t sock);

		template <typename Fn>
		socket_t create_socket(const char* host, int port, Fn fn, int socket_flags = 0)
		{
			// Get address info
			struct addrinfo hints;
			struct addrinfo* result;

			memset(&hints, 0, sizeof(struct addrinfo));
			hints.ai_family = AF_UNSPEC;
			hints.ai_socktype = SOCK_STREAM;
			hints.ai_flags = socket_flags;
			hints.ai_protocol = 0;

			auto service = std::to_string(port);

			if (getaddrinfo(host, service.c_str(), &hints, &result))
			{
				return INVALID_SOCKET;
			}

			for (auto rp = result; rp; rp = rp->ai_next)
			{
				// Create a socket
#ifdef _WIN32
				auto sock = WSASocketW(rp->ai_family, rp->ai_socktype, rp->ai_protocol,
					nullptr, 0, WSA_FLAG_NO_HANDLE_INHERIT);
				/**
				 * Since the WSA_FLAG_NO_HANDLE_INHERIT is only supported on Windows 7 SP1
				 * and above the socket creation fails on older Windows Systems.
				 *
				 * Let's try to create a socket the old way in this case.
				 *
				 * Reference:
				 * https://docs.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsasocketa
				 *
				 * WSA_FLAG_NO_HANDLE_INHERIT:
				 * This flag is supported on Windows 7 with SP1, Windows Server 2008 R2 with
				 * SP1, and later
				 *
				 */
				if (sock == INVALID_SOCKET)
				{
					sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
				}
#else
				auto sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
#endif
				if (sock == INVALID_SOCKET)
				{
					continue;
				}

#ifndef _WIN32
				if (fcntl(sock, F_SETFD, FD_CLOEXEC) == -1)
				{
					continue;
				}
#endif

				// Make 'reuse address' option available
				int yes = 1;
				setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<char*>(&yes),
					sizeof(yes));

#ifdef SO_REUSEPORT
				setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, reinterpret_cast<char*>(&yes),
					sizeof(yes));
#endif

				if (rp->ai_family == AF_INET6)
				{
					int no = 0;
					setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, reinterpret_cast<char*>(&no),
						sizeof(no));
				}

				// bind or connect
				if (fn(sock, *rp))
				{
					freeaddrinfo(result);
					return sock;
				}

				close_socket(sock);
			}

			freeaddrinfo(result);
			return INVALID_SOCKET;
		}

		void set_nonblocking(socket_t sock, bool nonblocking);

		bool is_connection_error();

		bool bind_ip_address(socket_t sock, const char* host);

#ifndef _WIN32
		std::string if2ip(const std::string& ifn);
#endif

		void get_remote_ip_and_port(const struct sockaddr_storage& addr, socklen_t addr_len, std::string& ip, int& port);

		void get_remote_ip_and_port(socket_t sock, std::string& ip, int& port);

		const char* find_content_type(const std::string& path, const std::map<std::string, std::string>& user_data);

		const char* status_message(int status);

#ifdef CPPHTTPLIB_ZLIB_SUPPORT
		bool can_compress(const std::string& content_type);

		bool compress(std::string& content);

		class decompressor
		{
		public:
			decompressor();

			~decompressor();

			bool is_valid() const;

			template <typename T>
			bool decompress(const char* data, size_t data_length, T callback)
			{
				int ret = Z_OK;

				strm.avail_in = static_cast<decltype(strm.avail_in)>(data_length);
				strm.next_in = const_cast<Bytef*>(reinterpret_cast<const Bytef*>(data));

				std::array<char, 16384> buff{};
				do
				{
					strm.avail_out = buff.size();
					strm.next_out = reinterpret_cast<Bytef*>(buff.data());

					ret = inflate(&strm, Z_NO_FLUSH);
					assert(ret != Z_STREAM_ERROR);
					switch (ret)
					{
					case Z_NEED_DICT:
					case Z_DATA_ERROR:
					case Z_MEM_ERROR: inflateEnd(&strm); return false;
					}

					if (!callback(buff.data(), buff.size() - strm.avail_out))
					{
						return false;
					}
				} while (strm.avail_out == 0);

				return ret == Z_OK || ret == Z_STREAM_END;
			}

		private:
			bool is_valid_;
			z_stream strm;
		};
#endif

		bool has_header(const Headers& headers, const char* key);

		const char* get_header_value(const Headers& headers, const char* key, size_t id = 0, const char* def = nullptr);

		uint64_t get_header_value_uint64(const Headers& headers, const char* key, uint64_t def = 0);

		void parse_header(const char* beg, const char* end, Headers& headers);

		bool read_headers(Stream& strm, Headers& headers);

		bool read_content_with_length(Stream& strm, uint64_t len, Progress progress, ContentReceiver out);

		void skip_content_with_length(Stream& strm, uint64_t len);

		bool read_content_without_length(Stream& strm, ContentReceiver out);

		bool read_content_chunked(Stream& strm, ContentReceiver out);

		bool is_chunked_transfer_encoding(const Headers& headers);

		template <typename T>
		bool read_content(Stream& strm, T& x, size_t payload_max_length, int& status, Progress progress, ContentReceiver receiver, bool decompress)
		{

			ContentReceiver out = [&](const char* buf, size_t n)
			{
				return receiver(buf, n);
			};

#ifdef CPPHTTPLIB_ZLIB_SUPPORT
			decompressor decompressor;
#endif

			if (decompress)
			{
#ifdef CPPHTTPLIB_ZLIB_SUPPORT
				std::string content_encoding = x.get_header_value("Content-Encoding");
				if (content_encoding.find("gzip") != std::string::npos ||
					content_encoding.find("deflate") != std::string::npos)
				{
					if (!decompressor.is_valid())
					{
						status = 500;
						return false;
					}

					out = [&](const char* buf, size_t n)
					{
						return decompressor.decompress(buf, n, [&](const char* buf, size_t n)
							{
								return receiver(buf, n);
							});
					};
				}
#else
				if (x.get_header_value("Content-Encoding") == "gzip")
				{
					status = 415;
					return false;
				}
#endif
			}

			auto ret = true;
			auto exceed_payload_max_length = false;

			if (is_chunked_transfer_encoding(x.headers))
			{
				ret = read_content_chunked(strm, out);
			}
			else if (!has_header(x.headers, "Content-Length"))
			{
				ret = read_content_without_length(strm, out);
			}
			else
			{
				auto len = get_header_value_uint64(x.headers, "Content-Length", 0);
				if (len > payload_max_length)
				{
					exceed_payload_max_length = true;
					skip_content_with_length(strm, len);
					ret = false;
				}
				else if (len > 0)
				{
					ret = read_content_with_length(strm, len, progress, out);
				}
			}

			if (!ret)
			{
				status = exceed_payload_max_length ? 413 : 400;
			}

			return ret;
		}

		template <typename T>
		ssize_t write_headers(Stream& strm, const T& info, const Headers& headers)
		{
			ssize_t write_len = 0;
			for (const auto& x : info.headers)
			{
				if (x.first == "EXCEPTION_WHAT")
				{
					continue;
				}
				auto len =
					strm.write_format("%s: %s\r\n", x.first.c_str(), x.second.c_str());
				if (len < 0)
				{
					return len;
				}
				write_len += len;
			}
			for (const auto& x : headers)
			{
				auto len =
					strm.write_format("%s: %s\r\n", x.first.c_str(), x.second.c_str());
				if (len < 0)
				{
					return len;
				}
				write_len += len;
			}
			auto len = strm.write("\r\n");
			if (len < 0)
			{
				return len;
			}
			write_len += len;
			return write_len;
		}

		bool write_data(Stream& strm, const char* d, size_t l);

		ssize_t write_content(Stream& strm, ContentProvider content_provider, size_t offset, size_t length);

		// Calls content_provider and writes data to the steam if counters.data_available is true.
		bool write_content_chunked(Stream& strm, ContentProvider content_provider, ChunkedContentCounters& counters);

		std::string encode_url(const std::string& s);

		std::string decode_url(const std::string& s, bool convert_plus_to_space);

		std::string params_to_query_str(const Params& params);

		void parse_query_text(const std::string& s, Params& params);

		bool parse_multipart_boundary(const std::string& content_type, std::string& boundary);

		bool parse_range_header(const std::string& s, Ranges& ranges);

		class MultipartFormDataParser
		{
		public:
			MultipartFormDataParser() = default;

			void set_boundary(std::string boundary);

			bool is_valid() const;

			template <typename T, typename U>
			bool parse(const char* buf, size_t n, T content_callback, U header_callback)
			{
				static const std::regex re_content_type(R"(^Content-Type:\s*(.*?)\s*$)",
					std::regex_constants::icase);

				static const std::regex re_content_disposition(
					"^Content-Disposition:\\s*form-data;\\s*name=\"(.*?)\"(?:;\\s*filename="
					"\"(.*?)\")?\\s*$",
					std::regex_constants::icase);
				static const std::string dash_ = "--";
				static const std::string crlf_ = "\r\n";

				buf_.append(buf, n); // TODO: performance improvement

				while (!buf_.empty())
				{
					switch (state_)
					{
					case 0:
					{ // Initial boundary
						auto pattern = dash_ + boundary_ + crlf_;
						if (pattern.size() > buf_.size())
						{
							return true;
						}
						auto pos = buf_.find(pattern);
						if (pos != 0)
						{
							is_done_ = true;
							return false;
						}
						buf_.erase(0, pattern.size());
						off_ += pattern.size();
						state_ = 1;
						break;
					}
					case 1:
					{ // New entry
						clear_file_info();
						state_ = 2;
						break;
					}
					case 2:
					{ // Headers
						auto pos = buf_.find(crlf_);
						while (pos != std::string::npos)
						{
							// Empty line
							if (pos == 0)
							{
								if (!header_callback(file_))
								{
									is_valid_ = false;
									is_done_ = false;
									return false;
								}
								buf_.erase(0, crlf_.size());
								off_ += crlf_.size();
								state_ = 3;
								break;
							}

							auto header = buf_.substr(0, pos);
							{
								std::smatch m;
								if (std::regex_match(header, m, re_content_type))
								{
									file_.content_type = m[1];
								}
								else if (std::regex_match(header, m, re_content_disposition))
								{
									file_.name = m[1];
									file_.filename = m[2];
								}
							}

							buf_.erase(0, pos + crlf_.size());
							off_ += pos + crlf_.size();
							pos = buf_.find(crlf_);
						}
						break;
					}
					case 3:
					{ // Body
						{
							auto pattern = crlf_ + dash_;
							if (pattern.size() > buf_.size())
							{
								return true;
							}

							auto pos = buf_.find(pattern);
							if (pos == std::string::npos)
							{
								pos = buf_.size();
							}
							if (!content_callback(buf_.data(), pos))
							{
								is_valid_ = false;
								is_done_ = false;
								return false;
							}

							off_ += pos;
							buf_.erase(0, pos);
						}

						{
							auto pattern = crlf_ + dash_ + boundary_;
							if (pattern.size() > buf_.size())
							{
								return true;
							}

							auto pos = buf_.find(pattern);
							if (pos != std::string::npos)
							{
								if (!content_callback(buf_.data(), pos))
								{
									is_valid_ = false;
									is_done_ = false;
									return false;
								}

								off_ += pos + pattern.size();
								buf_.erase(0, pos + pattern.size());
								state_ = 4;
							}
							else
							{
								if (!content_callback(buf_.data(), pattern.size()))
								{
									is_valid_ = false;
									is_done_ = false;
									return false;
								}

								off_ += pattern.size();
								buf_.erase(0, pattern.size());
							}
						}
						break;
					}
					case 4:
					{ // Boundary
						if (crlf_.size() > buf_.size())
						{
							return true;
						}
						if (buf_.find(crlf_) == 0)
						{
							buf_.erase(0, crlf_.size());
							off_ += crlf_.size();
							state_ = 1;
						}
						else
						{
							auto pattern = dash_ + crlf_;
							if (pattern.size() > buf_.size())
							{
								return true;
							}
							if (buf_.find(pattern) == 0)
							{
								buf_.erase(0, pattern.size());
								off_ += pattern.size();
								is_valid_ = true;
								state_ = 5;
							}
							else
							{
								is_done_ = true;
								return true;
							}
						}
						break;
					}
					case 5:
					{ // Done
						is_valid_ = false;
						return false;
					}
					}
				}

				return true;
			}

		private:
			void clear_file_info();

			std::string boundary_;

			std::string buf_;
			size_t state_ = 0;
			size_t is_valid_ = false;
			size_t is_done_ = false;
			size_t off_ = 0;
			MultipartFormData file_;
		};

		std::string to_lower(const char* beg, const char* end);

		std::string make_multipart_data_boundary();

		std::pair<size_t, size_t> get_range_offset_and_length(const Request& req, size_t content_length, size_t index);

		std::string make_content_range_header_field(size_t offset, size_t length, size_t content_length);

		template <typename SToken, typename CToken, typename Content>
		bool process_multipart_ranges_data(const Request& req, Response& res, const std::string& boundary, const std::string& content_type, SToken stoken, CToken ctoken, Content content)
		{
			for (size_t i = 0; i < req.ranges.size(); i++)
			{
				ctoken("--");
				stoken(boundary);
				ctoken("\r\n");
				if (!content_type.empty())
				{
					ctoken("Content-Type: ");
					stoken(content_type);
					ctoken("\r\n");
				}

				auto offsets = get_range_offset_and_length(req, res.body.size(), i);
				auto offset = offsets.first;
				auto length = offsets.second;

				ctoken("Content-Range: ");
				stoken(make_content_range_header_field(offset, length, res.body.size()));
				ctoken("\r\n");
				ctoken("\r\n");
				if (!content(offset, length))
				{
					return false;
				}
				ctoken("\r\n");
			}

			ctoken("--");
			stoken(boundary);
			ctoken("--\r\n");

			return true;
		}

		std::string make_multipart_ranges_data(const Request& req, Response& res, const std::string& boundary, const std::string& content_type);

		size_t get_multipart_ranges_data_length(const Request& req, Response& res, const std::string& boundary, const std::string& content_type);

		bool write_multipart_ranges_data(Stream& strm, const Request& req, Response& res, const std::string& boundary, const std::string& content_type);

		std::pair<size_t, size_t> get_range_offset_and_length(const Request& req, const Response& res, size_t index);

		bool expect_content(const Request& req);

		bool has_crlf(const char* s);

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
		template <typename CTX, typename Init, typename Update, typename Final>
		std::string message_digest(const std::string& s, Init init, Update update, Final final, size_t digest_length)
		{
			using namespace std;

			std::vector<unsigned char> md(digest_length, 0);
			CTX ctx;
			init(&ctx);
			update(&ctx, s.data(), s.size());
			final(md.data(), &ctx);

			stringstream ss;
			for (auto c : md)
			{
				ss << setfill('0') << setw(2) << hex << (unsigned int)c;
			}
			return ss.str();
		}

		std::string MD5(const std::string& s);

		std::string SHA_256(const std::string& s);

		std::string SHA_512(const std::string& s);
#endif

#ifdef _WIN32
		class WSInit
		{
		public:
			WSInit();
			~WSInit();
		};
#endif

	} // namespace detail

	inline timeval Duration2TimeVal(std::chrono::microseconds us)
	{
		timeval ret;
		ret.tv_sec = static_cast<decltype(ret.tv_sec)>(std::chrono::duration_cast<std::chrono::seconds>(us).count());
		ret.tv_usec = static_cast<decltype(ret.tv_usec)>(us.count() % ret.tv_sec);
		return ret;
	}

	// Header utilities
	std::pair<std::string, std::string> make_range_header(Ranges ranges);

	std::pair<std::string, std::string>	make_basic_authentication_header(const std::string& username, const std::string& password, bool is_proxy = false);

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
	std::pair<std::string, std::string> make_digest_authentication_header(
		const Request& req, const std::map<std::string, std::string>& auth,
		size_t cnonce_count, const std::string& cnonce, const std::string& username,
		const std::string& password, bool is_proxy = false);
#endif

	bool parse_www_authenticate(const httplib::Response& res, std::map<std::string, std::string>& auth, bool is_proxy);

	// https://stackoverflow.com/questions/440133/how-do-i-create-a-random-alpha-numeric-string-in-c/440240#answer-440240
	std::string random_string(size_t length);
}