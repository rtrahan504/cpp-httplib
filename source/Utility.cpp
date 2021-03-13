//
// Copyright (c) 2020 Yuji Hirose, 2021 Russell Trahan. All rights reserved. 
// Portions of this project have been copied from cpp-httplib by Yuji Hirose and modified by Russell Trahan.
//  
// MIT License
//

#include "Utility.h"

namespace httplib
{
	namespace detail
	{
		bool is_hex(char c, int& v)
		{
			if (0x20 <= c && isdigit(c))
			{
				v = c - '0';
				return true;
			}
			else if ('A' <= c && c <= 'F')
			{
				v = c - 'A' + 10;
				return true;
			}
			else if ('a' <= c && c <= 'f')
			{
				v = c - 'a' + 10;
				return true;
			}
			return false;
		}

		bool from_hex_to_i(const std::string& s, size_t i, size_t cnt, int& val)
		{
			if (i >= s.size())
			{
				return false;
			}

			val = 0;
			for (; cnt; i++, cnt--)
			{
				if (!s[i])
				{
					return false;
				}
				int v = 0;
				if (is_hex(s[i], v))
				{
					val = val * 16 + v;
				}
				else
				{
					return false;
				}
			}
			return true;
		}

		std::string from_i_to_hex(size_t n)
		{
			const char* charset = "0123456789abcdef";
			std::string ret;
			do
			{
				ret = charset[n & 15] + ret;
				n >>= 4;
			} while (n > 0);
			return ret;
		}

		size_t to_utf8(int code, char* buff)
		{
			if (code < 0x0080)
			{
				buff[0] = (code & 0x7F);
				return 1;
			}
			else if (code < 0x0800)
			{
				buff[0] = static_cast<char>(0xC0 | ((code >> 6) & 0x1F));
				buff[1] = static_cast<char>(0x80 | (code & 0x3F));
				return 2;
			}
			else if (code < 0xD800)
			{
				buff[0] = static_cast<char>(0xE0 | ((code >> 12) & 0xF));
				buff[1] = static_cast<char>(0x80 | ((code >> 6) & 0x3F));
				buff[2] = static_cast<char>(0x80 | (code & 0x3F));
				return 3;
			}
			else if (code < 0xE000)
			{ // D800 - DFFF is invalid...
				return 0;
			}
			else if (code < 0x10000)
			{
				buff[0] = static_cast<char>(0xE0 | ((code >> 12) & 0xF));
				buff[1] = static_cast<char>(0x80 | ((code >> 6) & 0x3F));
				buff[2] = static_cast<char>(0x80 | (code & 0x3F));
				return 3;
			}
			else if (code < 0x110000)
			{
				buff[0] = static_cast<char>(0xF0 | ((code >> 18) & 0x7));
				buff[1] = static_cast<char>(0x80 | ((code >> 12) & 0x3F));
				buff[2] = static_cast<char>(0x80 | ((code >> 6) & 0x3F));
				buff[3] = static_cast<char>(0x80 | (code & 0x3F));
				return 4;
			}

			// NOTREACHED
			return 0;
		}

		// NOTE: This code came up with the following stackoverflow post:
		// https://stackoverflow.com/questions/180947/base64-decode-snippet-in-c
		std::string base64_encode(const std::string& in)
		{
			static const auto lookup =
				"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

			std::string out;
			out.reserve(in.size());

			int val = 0;
			int valb = -6;

			for (auto c : in)
			{
				val = (val << 8) + static_cast<uint8_t>(c);
				valb += 8;
				while (valb >= 0)
				{
					out.push_back(lookup[(val >> valb) & 0x3F]);
					valb -= 6;
				}
			}

			if (valb > -6)
			{
				out.push_back(lookup[((val << 8) >> (valb + 8)) & 0x3F]);
			}

			while (out.size() % 4)
			{
				out.push_back('=');
			}

			return out;
		}

		bool is_file(std::string_view path)
		{
			struct stat st;
			return stat(path.data(), &st) >= 0 && S_ISREG(st.st_mode);
		}

		bool is_dir(std::string_view path)
		{
			struct stat st;
			return stat(path.data(), &st) >= 0 && S_ISDIR(st.st_mode);
		}

		bool is_valid_path(std::string_view path)
		{
			size_t level = 0;
			size_t i = 0;

			// Skip slash
			while (i < path.size() && path[i] == '/')
			{
				i++;
			}

			while (i < path.size())
			{
				// Read component
				auto beg = i;
				while (i < path.size() && path[i] != '/')
				{
					i++;
				}

				auto len = i - beg;
				assert(len > 0);

				if (!path.compare(beg, len, "."))
				{
					;
				}
				else if (!path.compare(beg, len, ".."))
				{
					if (level == 0)
					{
						return false;
					}
					level--;
				}
				else
				{
					level++;
				}

				// Skip slash
				while (i < path.size() && path[i] == '/')
				{
					i++;
				}
			}

			return true;
		}

		void read_file(std::string_view path, std::string& out)
		{
			std::ifstream fs(path.data(), std::ios_base::binary);
			fs.seekg(0, std::ios_base::end);
			auto size = fs.tellg();
			fs.seekg(0);
			out.resize(static_cast<size_t>(size));
			fs.read(&out[0], size);
		}

		std::string file_extension(const std::string& path)
		{
			std::smatch m;
			static auto re = std::regex("\\.([a-zA-Z0-9]+)$");
			if (std::regex_search(path, m, re))
			{
				return m[1].str();
			}
			return std::string();
		}

		// NOTE: until the read size reaches `fixed_buffer_size`, use `fixed_buffer`
		// to store data. The call can set memory on stack for performance.
		stream_line_reader::stream_line_reader(Stream& strm, char* fixed_buffer, size_t fixed_buffer_size)
			: strm_(strm), fixed_buffer_(fixed_buffer),
			fixed_buffer_size_(fixed_buffer_size)
		{
		}

		const char* stream_line_reader::ptr() const
		{
			if (glowable_buffer_.empty())
			{
				return fixed_buffer_;
			}
			else
			{
				return glowable_buffer_.data();
			}
		}

		size_t stream_line_reader::size() const
		{
			if (glowable_buffer_.empty())
			{
				return fixed_buffer_used_size_;
			}
			else
			{
				return glowable_buffer_.size();
			}
		}

		bool stream_line_reader::end_with_crlf() const
		{
			auto end = ptr() + size();
			return size() >= 2 && end[-2] == '\r' && end[-1] == '\n';
		}

		bool stream_line_reader::getline()
		{
			fixed_buffer_used_size_ = 0;
			glowable_buffer_.clear();

			for (size_t i = 0;; i++)
			{
				char byte;
				auto n = strm_.read(&byte, 1);

				if (n < 0)
				{
					return false;
				}
				else if (n == 0)
				{
					if (i == 0)
					{
						return false;
					}
					else
					{
						break;
					}
				}

				append(byte);

				if (byte == '\n')
				{
					break;
				}
			}

			return true;
		}

		void stream_line_reader::append(char c)
		{
			if (fixed_buffer_used_size_ < fixed_buffer_size_ - 1)
			{
				fixed_buffer_[fixed_buffer_used_size_++] = c;
				fixed_buffer_[fixed_buffer_used_size_] = '\0';
			}
			else
			{
				if (glowable_buffer_.empty())
				{
					assert(fixed_buffer_[fixed_buffer_used_size_] == '\0');
					glowable_buffer_.assign(fixed_buffer_, fixed_buffer_used_size_);
				}
				glowable_buffer_ += c;
			}
		}

		int close_socket(socket_t sock)
		{
#ifdef _WIN32
			return closesocket(sock);
#else
			return close(sock);
#endif
		}

		template <typename T> 
		ssize_t handle_EINTR(T fn)
		{
			ssize_t res = false;
			while (true)
			{
				res = fn();
				if (res < 0 && errno == EINTR)
				{
					continue;
				}
				break;
			}
			return res;
		}

		ssize_t select_read(socket_t sock, std::chrono::microseconds timeout)
		{
#ifdef CPPHTTPLIB_USE_POLL
			struct pollfd pfd_read;
			pfd_read.fd = sock;
			pfd_read.events = POLLIN;

			auto timeout = static_cast<int>(sec * 1000 + usec / 1000);

			return handle_EINTR([&]()
				{
					return poll(&pfd_read, 1, timeout);
				});
#else
			fd_set fds;
			FD_ZERO(&fds);
			FD_SET(sock, &fds);

			timeval tv = Duration2TimeVal(timeout);

			return handle_EINTR([&]()
				{
					return select(static_cast<int>(sock + 1), &fds, nullptr, nullptr, &tv);
				});
#endif
		}

		ssize_t select_write(socket_t sock, std::chrono::microseconds timeout)
		{
#ifdef CPPHTTPLIB_USE_POLL
			struct pollfd pfd_read;
			pfd_read.fd = sock;
			pfd_read.events = POLLOUT;

			auto timeout = static_cast<int>(sec * 1000 + usec / 1000);

			return handle_EINTR([&]()
				{
					return poll(&pfd_read, 1, timeout);
				});
#else
			fd_set fds;
			FD_ZERO(&fds);
			FD_SET(sock, &fds);

			timeval tv = Duration2TimeVal(timeout);

			return handle_EINTR([&]()
				{
					return select(static_cast<int>(sock + 1), nullptr, &fds, nullptr, &tv);
				});
#endif
		}

		bool wait_until_socket_is_ready(socket_t sock, std::chrono::microseconds timeout)
		{
#ifdef CPPHTTPLIB_USE_POLL
			struct pollfd pfd_read;
			pfd_read.fd = sock;
			pfd_read.events = POLLIN | POLLOUT;

			auto timeout = static_cast<int>(sec * 1000 + usec / 1000);

			auto poll_res = handle_EINTR([&]()
				{
					return poll(&pfd_read, 1, timeout);
				});

			if (poll_res > 0 && pfd_read.revents & (POLLIN | POLLOUT))
			{
				int error = 0;
				socklen_t len = sizeof(error);
				auto res = getsockopt(sock, SOL_SOCKET, SO_ERROR,
					reinterpret_cast<char*>(&error), &len);
				return res >= 0 && !error;
			}
			return false;
#else
			fd_set fdsr;
			FD_ZERO(&fdsr);
			FD_SET(sock, &fdsr);

			auto fdsw = fdsr;
			auto fdse = fdsr;

			timeval tv = Duration2TimeVal(timeout);

			auto ret = handle_EINTR([&]()
				{
					return select(static_cast<int>(sock + 1), &fdsr, &fdsw, &fdse, &tv);
				});

			if (ret > 0 && (FD_ISSET(sock, &fdsr) || FD_ISSET(sock, &fdsw)))
			{
				int error = 0;
				socklen_t len = sizeof(error);
				return getsockopt(sock, SOL_SOCKET, SO_ERROR,
					reinterpret_cast<char*>(&error), &len) >= 0 &&
					!error;
			}
			return false;
#endif
		}


		int shutdown_socket(socket_t sock)
		{
#ifdef _WIN32
			return shutdown(sock, SD_BOTH);
#else
			return shutdown(sock, SHUT_RDWR);
#endif
		}

		void set_nonblocking(socket_t sock, bool nonblocking)
		{
#ifdef _WIN32
			auto flags = nonblocking ? 1UL : 0UL;
			ioctlsocket(sock, FIONBIO, &flags);
#else
			auto flags = fcntl(sock, F_GETFL, 0);
			fcntl(sock, F_SETFL,
				nonblocking ? (flags | O_NONBLOCK) : (flags & (~O_NONBLOCK)));
#endif
		}

		bool is_connection_error()
		{
#ifdef _WIN32
			return WSAGetLastError() != WSAEWOULDBLOCK;
#else
			return errno != EINPROGRESS;
#endif
		}

		bool bind_ip_address(socket_t sock, const char* host)
		{
			struct addrinfo hints;
			struct addrinfo* result;

			memset(&hints, 0, sizeof(struct addrinfo));
			hints.ai_family = AF_UNSPEC;
			hints.ai_socktype = SOCK_STREAM;
			hints.ai_protocol = 0;

			if (getaddrinfo(host, "0", &hints, &result))
			{
				return false;
			}

			auto ret = false;
			for (auto rp = result; rp; rp = rp->ai_next)
			{
				const auto& ai = *rp;
				if (!::bind(sock, ai.ai_addr, static_cast<socklen_t>(ai.ai_addrlen)))
				{
					ret = true;
					break;
				}
			}

			freeaddrinfo(result);
			return ret;
		}

#ifndef _WIN32
		std::string if2ip(const std::string& ifn)
		{
			struct ifaddrs* ifap;
			getifaddrs(&ifap);
			for (auto ifa = ifap; ifa; ifa = ifa->ifa_next)
			{
				if (ifa->ifa_addr && ifn == ifa->ifa_name)
				{
					if (ifa->ifa_addr->sa_family == AF_INET)
					{
						auto sa = reinterpret_cast<struct sockaddr_in*>(ifa->ifa_addr);
						char buf[INET_ADDRSTRLEN];
						if (inet_ntop(AF_INET, &sa->sin_addr, buf, INET_ADDRSTRLEN))
						{
							freeifaddrs(ifap);
							return std::string(buf, INET_ADDRSTRLEN);
						}
					}
				}
			}
			freeifaddrs(ifap);
			return std::string();
		}
#endif

		void get_remote_ip_and_port(const struct sockaddr_storage& addr, socklen_t addr_len, std::string& ip, int& port)
		{
			if (addr.ss_family == AF_INET)
			{
				port = ntohs(reinterpret_cast<const struct sockaddr_in*>(&addr)->sin_port);
			}
			else if (addr.ss_family == AF_INET6)
			{
				port =
					ntohs(reinterpret_cast<const struct sockaddr_in6*>(&addr)->sin6_port);
			}

			std::array<char, NI_MAXHOST> ipstr{};
			if (!getnameinfo(reinterpret_cast<const struct sockaddr*>(&addr), addr_len,
				ipstr.data(), static_cast<socklen_t>(ipstr.size()), nullptr,
				0, NI_NUMERICHOST))
			{
				ip = ipstr.data();
			}
		}

		void get_remote_ip_and_port(socket_t sock, std::string& ip, int& port)
		{
			struct sockaddr_storage addr;
			socklen_t addr_len = sizeof(addr);

			if (!getpeername(sock, reinterpret_cast<struct sockaddr*>(&addr),
				&addr_len))
			{
				get_remote_ip_and_port(addr, addr_len, ip, port);
			}
		}

		const char* find_content_type(const std::string& path, const std::map<std::string, std::string>& user_data)
		{
			auto ext = file_extension(path);

			auto it = user_data.find(ext);
			if (it != user_data.end())
			{
				return it->second.c_str();
			}

			if (ext == "txt")
			{
				return "text/plain";
			}
			else if (ext == "html" || ext == "htm")
			{
				return "text/html";
			}
			else if (ext == "css")
			{
				return "text/css";
			}
			else if (ext == "jpeg" || ext == "jpg")
			{
				return "image/jpg";
			}
			else if (ext == "png")
			{
				return "image/png";
			}
			else if (ext == "gif")
			{
				return "image/gif";
			}
			else if (ext == "svg")
			{
				return "image/svg+xml";
			}
			else if (ext == "ico")
			{
				return "image/x-icon";
			}
			else if (ext == "json")
			{
				return "application/json";
			}
			else if (ext == "pdf")
			{
				return "application/pdf";
			}
			else if (ext == "js")
			{
				return "application/javascript";
			}
			else if (ext == "wasm")
			{
				return "application/wasm";
			}
			else if (ext == "xml")
			{
				return "application/xml";
			}
			else if (ext == "xhtml")
			{
				return "application/xhtml+xml";
			}
			return nullptr;
		}

		const char* status_message(int status)
		{
			switch (status)
			{
			case 100: return "Continue";
			case 101: return "Switching Protocol";
			case 102: return "Processing";
			case 103: return "Early Hints";
			case 200: return "OK";
			case 201: return "Created";
			case 202: return "Accepted";
			case 203: return "Non-Authoritative Information";
			case 204: return "No Content";
			case 205: return "Reset Content";
			case 206: return "Partial Content";
			case 207: return "Multi-Status";
			case 208: return "Already Reported";
			case 226: return "IM Used";
			case 300: return "Multiple Choice";
			case 301: return "Moved Permanently";
			case 302: return "Found";
			case 303: return "See Other";
			case 304: return "Not Modified";
			case 305: return "Use Proxy";
			case 306: return "unused";
			case 307: return "Temporary Redirect";
			case 308: return "Permanent Redirect";
			case 400: return "Bad Request";
			case 401: return "Unauthorized";
			case 402: return "Payment Required";
			case 403: return "Forbidden";
			case 404: return "Not Found";
			case 405: return "Method Not Allowed";
			case 406: return "Not Acceptable";
			case 407: return "Proxy Authentication Required";
			case 408: return "Request Timeout";
			case 409: return "Conflict";
			case 410: return "Gone";
			case 411: return "Length Required";
			case 412: return "Precondition Failed";
			case 413: return "Payload Too Large";
			case 414: return "URI Too Long";
			case 415: return "Unsupported Media Type";
			case 416: return "Range Not Satisfiable";
			case 417: return "Expectation Failed";
			case 418: return "I'm a teapot";
			case 421: return "Misdirected Request";
			case 422: return "Unprocessable Entity";
			case 423: return "Locked";
			case 424: return "Failed Dependency";
			case 425: return "Too Early";
			case 426: return "Upgrade Required";
			case 428: return "Precondition Required";
			case 429: return "Too Many Requests";
			case 431: return "Request Header Fields Too Large";
			case 451: return "Unavailable For Legal Reasons";
			case 501: return "Not Implemented";
			case 502: return "Bad Gateway";
			case 503: return "Service Unavailable";
			case 504: return "Gateway Timeout";
			case 505: return "HTTP Version Not Supported";
			case 506: return "Variant Also Negotiates";
			case 507: return "Insufficient Storage";
			case 508: return "Loop Detected";
			case 510: return "Not Extended";
			case 511: return "Network Authentication Required";

			default:
			case 500: return "Internal Server Error";
			}
		}

#ifdef CPPHTTPLIB_ZLIB_SUPPORT
		bool can_compress(const std::string& content_type)
		{
			return !content_type.find("text/") || content_type == "image/svg+xml" ||
				content_type == "application/javascript" ||
				content_type == "application/json" ||
				content_type == "application/xml" ||
				content_type == "application/xhtml+xml";
		}

		bool compress(std::string& content)
		{
			z_stream strm;
			strm.zalloc = Z_NULL;
			strm.zfree = Z_NULL;
			strm.opaque = Z_NULL;

			auto ret = deflateInit2(&strm, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 31, 8,
				Z_DEFAULT_STRATEGY);
			if (ret != Z_OK)
			{
				return false;
			}

			strm.avail_in = static_cast<decltype(strm.avail_in)>(content.size());
			strm.next_in =
				const_cast<Bytef*>(reinterpret_cast<const Bytef*>(content.data()));

			std::string compressed;

			std::array<char, 16384> buff{};
			do
			{
				strm.avail_out = buff.size();
				strm.next_out = reinterpret_cast<Bytef*>(buff.data());
				ret = deflate(&strm, Z_FINISH);
				assert(ret != Z_STREAM_ERROR);
				compressed.append(buff.data(), buff.size() - strm.avail_out);
			} while (strm.avail_out == 0);

			assert(ret == Z_STREAM_END);
			assert(strm.avail_in == 0);

			content.swap(compressed);

			deflateEnd(&strm);
			return true;
		}

		decompressor::decompressor()
		{
			std::memset(&strm, 0, sizeof(strm));
			strm.zalloc = Z_NULL;
			strm.zfree = Z_NULL;
			strm.opaque = Z_NULL;

			// 15 is the value of wbits, which should be at the maximum possible value
			// to ensure that any gzip stream can be decoded. The offset of 32 specifies
			// that the stream type should be automatically detected either gzip or
			// deflate.
			is_valid_ = inflateInit2(&strm, 32 + 15) == Z_OK;
		}

		decompressor::~decompressor()
		{
			inflateEnd(&strm);
		}

		bool decompressor::is_valid() const
		{
			return is_valid_;
		}
#endif

		bool has_header(const Headers& headers, std::string_view key)
		{
			return headers.find(key.data()) != headers.end();
		}

		const char* get_header_value(const Headers& headers, std::string_view key, size_t id, std::string_view def)
		{
			auto it = headers.find(key.data());
			std::advance(it, static_cast<int>(id));
			if (it != headers.end())
			{
				return it->second.c_str();
			}
			return def.data();
		}

		uint64_t get_header_value_uint64(const Headers& headers, std::string_view key, uint64_t def)
		{
			auto it = headers.find(key.data());
			if (it != headers.end())
			{
				return std::strtoull(it->second.data(), nullptr, 10);
			}
			return def;
		}

		void parse_header(const char* beg, const char* end, Headers& headers)
		{
			auto p = beg;
			while (p < end && *p != ':')
			{
				p++;
			}
			if (p < end)
			{
				auto key_end = p;
				p++; // skip ':'
				while (p < end && (*p == ' ' || *p == '\t'))
				{
					p++;
				}
				if (p < end)
				{
					auto val_begin = p;
					while (p < end)
					{
						p++;
					}
					headers.emplace(std::string(beg, key_end), std::string(val_begin, end));
				}
			}
		}

		bool read_headers(Stream& strm, Headers& headers)
		{
			const auto bufsiz = 2048;
			char buf[bufsiz];
			stream_line_reader line_reader(strm, buf, bufsiz);

			for (;;)
			{
				if (!line_reader.getline())
				{
					return false;
				}

				// Check if the line ends with CRLF.
				if (line_reader.end_with_crlf())
				{
					// Blank line indicates end of headers.
					if (line_reader.size() == 2)
					{
						break;
					}
				}
				else
				{
					continue; // Skip invalid line.
				}

				// Skip trailing spaces and tabs.
				auto end = line_reader.ptr() + line_reader.size() - 2;
				while (line_reader.ptr() < end && (end[-1] == ' ' || end[-1] == '\t'))
				{
					end--;
				}

				parse_header(line_reader.ptr(), end, headers);
			}

			return true;
		}

		constexpr size_t CPPHTTPLIB_RECV_BUFSIZ = 4096;

		bool read_content_with_length(Stream& strm, uint64_t len, Progress progress, ContentReceiver out)
		{
			char buf[CPPHTTPLIB_RECV_BUFSIZ];

			uint64_t r = 0;
			while (r < len)
			{
				auto read_len = static_cast<size_t>(len - r);
				auto n = strm.read(buf, (std::min)(read_len, CPPHTTPLIB_RECV_BUFSIZ));
				if (n <= 0)
				{
					return false;
				}

				if (!out(std::string_view(buf, static_cast<size_t>(n))))
				{
					return false;
				}

				r += static_cast<uint64_t>(n);

				if (progress)
				{
					if (!progress(r, len))
					{
						return false;
					}
				}
			}

			return true;
		}

		void skip_content_with_length(Stream& strm, uint64_t len)
		{
			char buf[CPPHTTPLIB_RECV_BUFSIZ];
			uint64_t r = 0;
			while (r < len)
			{
				auto read_len = static_cast<size_t>(len - r);
				auto n = strm.read(buf, (std::min)(read_len, CPPHTTPLIB_RECV_BUFSIZ));
				if (n <= 0)
				{
					return;
				}
				r += static_cast<uint64_t>(n);
			}
		}

		bool read_content_without_length(Stream& strm, ContentReceiver out)
		{
			char buf[CPPHTTPLIB_RECV_BUFSIZ];
			for (;;)
			{
				auto n = strm.read(buf, CPPHTTPLIB_RECV_BUFSIZ);
				if (n < 0)
				{
					return false;
				}
				else if (n == 0)
				{
					return true;
				}
				if (!out(std::string_view(buf, static_cast<size_t>(n))))
				{
					return false;
				}
			}

			return true;
		}

		bool read_content_chunked(Stream& strm, ContentReceiver out)
		{
			const auto bufsiz = 16;
			char buf[bufsiz];

			stream_line_reader line_reader(strm, buf, bufsiz);

			if (!line_reader.getline())
			{
				return false;
			}

			unsigned long chunk_len;
			while (true)
			{
				char* end_ptr;

				chunk_len = std::strtoul(line_reader.ptr(), &end_ptr, 16);

				if (end_ptr == line_reader.ptr())
				{
					return false;
				}
				if (chunk_len == ULONG_MAX)
				{
					return false;
				}

				if (chunk_len == 0)
				{
					break;
				}

				if (!read_content_with_length(strm, chunk_len, nullptr, out))
				{
					return false;
				}

				if (!line_reader.getline())
				{
					return false;
				}

				if (strcmp(line_reader.ptr(), "\r\n"))
				{
					break;
				}

				if (!line_reader.getline())
				{
					return false;
				}
			}

			if (chunk_len == 0)
			{
				// Reader terminator after chunks
				if (!line_reader.getline() || strcmp(line_reader.ptr(), "\r\n"))
					return false;
			}

			return true;
		}

		bool is_chunked_transfer_encoding(const Headers& headers)
		{
			return !strcasecmp(get_header_value(headers, "Transfer-Encoding", 0, ""),
				"chunked");
		}

		bool write_data(Stream& strm, std::string_view s)
		{
			size_t offset = 0;
			while (offset < s.size())
			{
				auto length = strm.write(std::string_view(s.data() + offset, s.size() - offset));
				if (length < 0)
				{
					return false;
				}
				offset += static_cast<size_t>(length);
			}
			return true;
		}

		ssize_t write_content(Stream& strm, ContentProvider content_provider, size_t offset, size_t length)
		{
			size_t begin_offset = offset;
			size_t end_offset = offset + length;

			auto ok = true;

			DataSink data_sink(
				[&](std::string_view s)
				{
					if (ok)
					{
						offset += s.size();
						if (!write_data(strm, s))
						{
							ok = false;
						}
					}
				},
				[&]() {},
					[&](void)
				{
					return ok && strm.is_writable();
				});

			while (ok && offset < end_offset)
			{
				if (!content_provider(offset, end_offset - offset, data_sink))
				{
					return -1;
				}
				if (!ok)
				{
					return -1;
				}
			}

			return static_cast<ssize_t>(offset - begin_offset);
		}

		// Calls content_provider and writes data to the steam if counters.data_available is true.
		bool write_content_chunked(Stream& strm, ContentProvider content_provider, ChunkedContentCounters& counters)
		{
			if (counters.data_available)
			{
				DataSink data_sink(
					[&](std::string_view s)
					{
						if (counters.ok)
						{
							counters.data_available = s.size() > 0;
							counters.offset += s.size();

							// Emit chunked response header and footer for each chunk
							std::string chunk;
							chunk.reserve(s.size() + 10);
							chunk = from_i_to_hex(s.size()) + "\r\n";
							chunk += s;
							chunk += "\r\n";
							if (write_data(strm, chunk))
								counters.total_written_length += chunk.size();
							else
								counters.ok = false;
						}
					},
					[&]()
					{
						counters.data_available = false;
						if (counters.ok)
						{
							static std::string_view done_marker("0\r\n\r\n");
							if (write_data(strm, done_marker))
								counters.total_written_length += done_marker.size();
							else
								counters.ok = false;
						}
					},
						[&]()
					{
						return counters.ok && strm.is_writable();
					});

				if (!content_provider(counters.offset, 0, data_sink) || !counters.ok)
					return false;
			}

			return true;
		}

		std::string encode_url(const std::string& s)
		{
			std::string result;

			for (size_t i = 0; s[i]; i++)
			{
				switch (s[i])
				{
				case ' ': result += "%20"; break;
				case '+': result += "%2B"; break;
				case '\r': result += "%0D"; break;
				case '\n': result += "%0A"; break;
				case '\'': result += "%27"; break;
				case ',': result += "%2C"; break;
					// case ':': result += "%3A"; break; // ok? probably...
				case ';': result += "%3B"; break;
				default:
					auto c = static_cast<uint8_t>(s[i]);
					if (c >= 0x80)
					{
						result += '%';
						char hex[4];
						auto len = snprintf(hex, sizeof(hex) - 1, "%02X", c);
						assert(len == 2);
						result.append(hex, static_cast<size_t>(len));
					}
					else
					{
						result += s[i];
					}
					break;
				}
			}

			return result;
		}

		std::string decode_url(const std::string& s, bool convert_plus_to_space)
		{
			std::string result;

			for (size_t i = 0; i < s.size(); i++)
			{
				if (s[i] == '%' && i + 1 < s.size())
				{
					if (s[i + 1] == 'u')
					{
						int val = 0;
						if (from_hex_to_i(s, i + 2, 4, val))
						{
							// 4 digits Unicode codes
							char buff[4];
							size_t len = to_utf8(val, buff);
							if (len > 0)
							{
								result.append(buff, len);
							}
							i += 5; // 'u0000'
						}
						else
						{
							result += s[i];
						}
					}
					else
					{
						int val = 0;
						if (from_hex_to_i(s, i + 1, 2, val))
						{
							// 2 digits hex codes
							result += static_cast<char>(val);
							i += 2; // '00'
						}
						else
						{
							result += s[i];
						}
					}
				}
				else if (convert_plus_to_space && s[i] == '+')
				{
					result += ' ';
				}
				else
				{
					result += s[i];
				}
			}

			return result;
		}

		std::string params_to_query_str(const Params& params)
		{
			std::string query;

			for (auto it = params.begin(); it != params.end(); ++it)
			{
				if (it != params.begin())
				{
					query += "&";
				}
				query += it->first;
				query += "=";
				query += detail::encode_url(it->second);
			}

			return query;
		}

		void parse_query_text(const std::string& s, Params& params)
		{
			split(&s[0], &s[s.size()], '&', [&](const char* b, const char* e)
				{
					std::string key;
					std::string val;
					split(b, e, '=', [&](const char* b2, const char* e2)
						{
							if (key.empty())
							{
								key.assign(b2, e2);
							}
							else
							{
								val.assign(b2, e2);
							}
						});
					params.emplace(decode_url(key, true), decode_url(val, true));
				});
		}

		bool parse_multipart_boundary(const std::string& content_type, std::string& boundary)
		{
			auto pos = content_type.find("boundary=");
			if (pos == std::string::npos)
			{
				return false;
			}

			boundary = content_type.substr(pos + 9);
			return true;
		}

		bool parse_range_header(const std::string& s, Ranges& ranges)
		{
			static auto re_first_range = std::regex(R"(bytes=(\d*-\d*(?:,\s*\d*-\d*)*))");
			std::smatch m;
			if (std::regex_match(s, m, re_first_range))
			{
				auto pos = static_cast<size_t>(m.position(1));
				auto len = static_cast<size_t>(m.length(1));
				bool all_valid_ranges = true;
				split(&s[pos], &s[pos + len], ',', [&](const char* b, const char* e)
					{
						if (!all_valid_ranges) return;
						static auto re_another_range = std::regex(R"(\s*(\d*)-(\d*))");
						std::cmatch cm;
						if (std::regex_match(b, e, cm, re_another_range))
						{
							ssize_t first = -1;
							if (!cm.str(1).empty())
							{
								first = static_cast<ssize_t>(std::stoll(cm.str(1)));
							}

							ssize_t last = -1;
							if (!cm.str(2).empty())
							{
								last = static_cast<ssize_t>(std::stoll(cm.str(2)));
							}

							if (first != -1 && last != -1 && first > last)
							{
								all_valid_ranges = false;
								return;
							}
							ranges.emplace_back(std::make_pair(first, last));
						}
					});
				return all_valid_ranges;
			}
			return false;
		}

		void MultipartFormDataParser::set_boundary(std::string boundary)
		{
			boundary_ = std::move(boundary);
		}

		bool MultipartFormDataParser::is_valid() const
		{
			return is_valid_;
		}

		void MultipartFormDataParser::clear_file_info()
		{
			file_.name.clear();
			file_.filename.clear();
			file_.content_type.clear();
		}

		std::string to_lower(const char* beg, const char* end)
		{
			std::string out;
			auto it = beg;
			while (it != end)
			{
				out += static_cast<char>(::tolower(*it));
				it++;
			}
			return out;
		}

		std::string make_multipart_data_boundary()
		{
			static const char data[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

			std::random_device seed_gen;
			std::mt19937 engine(seed_gen());

			std::string result = "--cpp-httplib-multipart-data-";

			for (auto i = 0; i < 16; i++)
			{
				result += data[engine() % (sizeof(data) - 1)];
			}

			return result;
		}

		std::pair<size_t, size_t> get_range_offset_and_length(const Request& req, size_t content_length, size_t index)
		{
			auto r = req.ranges[index];

			if (r.first == -1 && r.second == -1)
			{
				return std::make_pair(0, content_length);
			}

			auto slen = static_cast<ssize_t>(content_length);

			if (r.first == -1)
			{
				r.first = slen - r.second;
				r.second = slen - 1;
			}

			if (r.second == -1)
			{
				r.second = slen - 1;
			}

			return std::make_pair(r.first, r.second - r.first + 1);
		}

		std::string make_content_range_header_field(size_t offset, size_t length, size_t content_length)
		{
			std::string field = "bytes ";
			field += std::to_string(offset);
			field += "-";
			field += std::to_string(offset + length - 1);
			field += "/";
			field += std::to_string(content_length);
			return field;
		}

		std::string make_multipart_ranges_data(const Request& req, Response& res, const std::string& boundary, const std::string& content_type)
		{
			std::string data;

			process_multipart_ranges_data(
				req, res, boundary, content_type,
				[&](const std::string& token)
				{
					data += token;
				},
				[&](const char* token)
				{
					data += token;
				},
				[&](size_t offset, size_t length)
				{
					data += res.body.substr(offset, length);
					return true;
				});

			return data;
		}

		size_t get_multipart_ranges_data_length(const Request& req, Response& res, const std::string& boundary, const std::string& content_type)
		{
			size_t data_length = 0;

			process_multipart_ranges_data(
				req, res, boundary, content_type,
				[&](const std::string& token)
				{
					data_length += token.size();
				},
				[&](const char* token)
				{
					data_length += strlen(token);
				},
					[&](size_t /*offset*/, size_t length)
				{
					data_length += length;
					return true;
				});

			return data_length;
		}

		bool write_multipart_ranges_data(Stream& strm, const Request& req, Response& res, const std::string& boundary, const std::string& content_type)
		{
			return process_multipart_ranges_data(
				req, res, boundary, content_type,
				[&](const std::string& token)
				{
					strm.write(token);
				},
				[&](const char* token)
				{
					strm.write(token);
				},
					[&](size_t offset, size_t length)
				{
					return write_content(strm, res.GetContentProvider(), offset, length) >= 0;
				});
		}

		std::pair<size_t, size_t> get_range_offset_and_length(const Request& req, const Response& res, size_t index)
		{
			auto r = req.ranges[index];

			if (r.second == -1)
			{
				r.second = static_cast<ssize_t>(res.GetContentLength()) - 1;
			}

			return std::make_pair(r.first, r.second - r.first + 1);
		}

		bool expect_content(const Request& req)
		{
			if (req.method == "POST" || req.method == "PUT" || req.method == "PATCH" ||
				req.method == "PRI" ||
				(req.method == "DELETE" && req.has_header("Content-Length")))
			{
				return true;
			}
			// TODO: check if Content-Length is set
			return false;
		}

		bool has_crlf(std::string_view s)
		{
			for(auto& c : s)
			{
				if (c == '\r' || c == '\n')
					return true;
			}
			return false;
		}

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
		std::string MD5(const std::string& s)
		{
			return message_digest<MD5_CTX>(s, MD5_Init, MD5_Update, MD5_Final, MD5_DIGEST_LENGTH);
		}

		std::string SHA_256(const std::string& s)
		{
			return message_digest<SHA256_CTX>(s, SHA256_Init, SHA256_Update, SHA256_Final, SHA256_DIGEST_LENGTH);
		}

		std::string SHA_512(const std::string& s)
		{
			return message_digest<SHA512_CTX>(s, SHA512_Init, SHA512_Update, SHA512_Final, SHA512_DIGEST_LENGTH);
		}
#endif

#ifdef _WIN32
		WSInit::WSInit()
		{
			WSADATA wsaData;
			WSAStartup(0x0002, &wsaData);
		}

		WSInit::~WSInit()
		{
			WSACleanup();
		}

		static WSInit wsinit_;
#endif

	} // namespace detail

	// Header utilities
	std::pair<std::string, std::string> make_range_header(Ranges ranges)
	{
		std::string field = "bytes=";
		auto i = 0;
		for (auto r : ranges)
		{
			if (i != 0)
			{
				field += ", ";
			}
			if (r.first != -1)
			{
				field += std::to_string(r.first);
			}
			field += '-';
			if (r.second != -1)
			{
				field += std::to_string(r.second);
			}
			i++;
		}
		return std::make_pair("Range", field);
	}

	std::pair<std::string, std::string>	make_basic_authentication_header(const std::string& username, const std::string& password, bool is_proxy)
	{
		auto field = "Basic " + detail::base64_encode(username + ":" + password);
		auto key = is_proxy ? "Proxy-Authorization" : "Authorization";
		return std::make_pair(key, field);
	}

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
	std::pair<std::string, std::string> make_digest_authentication_header(
		const Request& req, const std::map<std::string, std::string>& auth,
		size_t cnonce_count, const std::string& cnonce, const std::string& username,
		const std::string& password, bool is_proxy)
	{
		using namespace std;

		string nc;
		{
			stringstream ss;
			ss << setfill('0') << setw(8) << hex << cnonce_count;
			nc = ss.str();
		}

		auto qop = auth.at("qop");
		if (qop.find("auth-int") != std::string::npos)
		{
			qop = "auth-int";
		}
		else
		{
			qop = "auth";
		}

		std::string algo = "MD5";
		if (auth.find("algorithm") != auth.end())
		{
			algo = auth.at("algorithm");
		}

		string response;
		{
			auto H = algo == "SHA-256"
				? detail::SHA_256
				: algo == "SHA-512" ? detail::SHA_512 : detail::MD5;

			auto A1 = username + ":" + auth.at("realm") + ":" + password;

			auto A2 = req.method + ":" + req.path;
			if (qop == "auth-int")
			{
				A2 += ":" + H(req.body);
			}

			response = H(H(A1) + ":" + auth.at("nonce") + ":" + nc + ":" + cnonce +
				":" + qop + ":" + H(A2));
		}

		auto field = "Digest username=\"" + username + "\", realm=\"" +
			auth.at("realm") + "\", nonce=\"" + auth.at("nonce") +
			"\", uri=\"" + req.path + "\", algorithm=" + algo +
			", qop=" + qop + ", nc=\"" + nc + "\", cnonce=\"" + cnonce +
			"\", response=\"" + response + "\"";

		auto key = is_proxy ? "Proxy-Authorization" : "Authorization";
		return std::make_pair(key, field);
	}
#endif

	bool parse_www_authenticate(const httplib::Response& res, std::map<std::string, std::string>& auth, bool is_proxy)
	{
		auto auth_key = is_proxy ? "Proxy-Authenticate" : "WWW-Authenticate";
		if (res.has_header(auth_key))
		{
			static auto re = std::regex(R"~((?:(?:,\s*)?(.+?)=(?:"(.*?)"|([^,]*))))~");
			auto s = res.get_header_value(auth_key);
			auto pos = s.find(' ');
			if (pos != std::string::npos)
			{
				auto type = s.substr(0, pos);
				if (type == "Basic")
				{
					return false;
				}
				else if (type == "Digest")
				{
					s = s.substr(pos + 1);
					auto beg = std::sregex_iterator(s.begin(), s.end(), re);
					for (auto i = beg; i != std::sregex_iterator(); ++i)
					{
						auto m = *i;
						auto key = s.substr(static_cast<size_t>(m.position(1)),
							static_cast<size_t>(m.length(1)));
						auto val = m.length(2) > 0
							? s.substr(static_cast<size_t>(m.position(2)),
								static_cast<size_t>(m.length(2)))
							: s.substr(static_cast<size_t>(m.position(3)),
								static_cast<size_t>(m.length(3)));
						auth[key] = val;
					}
					return true;
				}
			}
		}
		return false;
	}

	// https://stackoverflow.com/questions/440133/how-do-i-create-a-random-alpha-numeric-string-in-c/440240#answer-440240
	std::string random_string(size_t length)
	{
		auto randchar = []() -> char
		{
			const char charset[] = "0123456789"
				"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
				"abcdefghijklmnopqrstuvwxyz";
			const size_t max_index = (sizeof(charset) - 1);
			return charset[static_cast<size_t>(rand()) % max_index];
		};
		std::string str(length, 0);
		std::generate_n(str.begin(), length, randchar);
		return str;
	}


	namespace detail
	{
		// Socket stream implementation
		SocketStream::SocketStream(socket_t sock, std::chrono::microseconds readTimeout, std::chrono::microseconds writeTimeout) : 
			sock_(sock), 
			m_ReadTimeout(readTimeout),
			m_WriteTimeout(writeTimeout)
		{
		}

		SocketStream::~SocketStream()
		{
		}

		bool SocketStream::is_readable() const
		{
			return select_read(sock_, m_ReadTimeout) > 0;
		}

		bool SocketStream::is_writable() const
		{
			return select_write(sock_, m_WriteTimeout) > 0;
		}

		ssize_t SocketStream::read(char* ptr, size_t size)
		{
			if (!is_readable())
			{
				return -1;
			}

#ifdef _WIN32
			if (size > static_cast<size_t>((std::numeric_limits<int>::max)()))
			{
				return -1;
			}
			return recv(sock_, ptr, static_cast<int>(size), 0);
#else
			return handle_EINTR([&]()
				{
					return recv(sock_, ptr, size, 0);
				});
#endif
		}

		ssize_t SocketStream::write(std::string_view s)
		{
			if (!is_writable())
			{
				return -1;
			}

#ifdef _WIN32
			if (s.size() > static_cast<size_t>((std::numeric_limits<int>::max)()))
			{
				return -1;
			}
			return send(sock_, s.data(), static_cast<int>(s.size()), 0);
#else
			return handle_EINTR([&]()
				{
					return send(sock_, ptr, size, 0);
				});
#endif
		}

		void SocketStream::get_remote_ip_and_port(std::string& ip, int& port) const
		{
			return detail::get_remote_ip_and_port(sock_, ip, port);
		}

		// Buffer stream implementation
		bool BufferStream::is_readable() const
		{
			return true;
		}

		bool BufferStream::is_writable() const
		{
			return true;
		}

		ssize_t BufferStream::read(char* ptr, size_t size)
		{
#if defined(_MSC_VER) && _MSC_VER < 1900
			auto len_read = buffer._Copy_s(ptr, size, size, position);
#else
			auto len_read = buffer.copy(ptr, size, position);
#endif
			position += static_cast<size_t>(len_read);
			return static_cast<ssize_t>(len_read);
		}

		ssize_t BufferStream::write(std::string_view s)
		{
			buffer.append(s.data(), s.size());
			return static_cast<ssize_t>(s.size());
		}

		void BufferStream::get_remote_ip_and_port(std::string& /*ip*/, int& /*port*/) const
		{
		}

		const std::string& BufferStream::get_buffer() const
		{
			return buffer;
		}

	}
}