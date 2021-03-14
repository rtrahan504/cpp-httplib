//
// Copyright (c) 2020 Yuji Hirose, 2021 Russell Trahan. All rights reserved. 
// Portions of this project have been copied from cpp-httplib by Yuji Hirose and modified by Russell Trahan.
//  
// MIT License
//

#include "Server.h"
#include "Utility.h"

namespace httplib
{
	// HTTP server implementation
	Server::Server() : is_running_(false), svr_sock_(INVALID_SOCKET)
	{
#ifndef _WIN32
		signal(SIGPIPE, SIG_IGN);
#endif
	}

	Server::~Server()
	{
	}

	Server& Server::Get(std::string_view pattern, Handler handler)
	{
		get_handlers_.push_back(std::make_pair(std::regex(pattern.data()), handler));
		return *this;
	}

	Server& Server::Post(std::string_view pattern, Handler handler)
	{
		post_handlers_.push_back(std::make_pair(std::regex(pattern.data()), handler));
		return *this;
	}

	Server& Server::Post(std::string_view pattern, HandlerWithContentReader handler)
	{
		post_handlers_for_content_reader_.push_back(std::make_pair(std::regex(pattern.data()), handler));
		return *this;
	}

	Server& Server::Put(std::string_view pattern, Handler handler)
	{
		put_handlers_.push_back(std::make_pair(std::regex(pattern.data()), handler));
		return *this;
	}

	Server& Server::Put(std::string_view pattern, HandlerWithContentReader handler)
	{
		put_handlers_for_content_reader_.push_back(std::make_pair(std::regex(pattern.data()), handler));
		return *this;
	}

	Server& Server::Patch(std::string_view pattern, Handler handler)
	{
		patch_handlers_.push_back(std::make_pair(std::regex(pattern.data()), handler));
		return *this;
	}

	Server& Server::Patch(std::string_view pattern, HandlerWithContentReader handler)
	{
		patch_handlers_for_content_reader_.push_back(std::make_pair(std::regex(pattern.data()), handler));
		return *this;
	}

	Server& Server::Delete(std::string_view pattern, Handler handler)
	{
		delete_handlers_.push_back(std::make_pair(std::regex(pattern.data()), handler));
		return *this;
	}

	Server& Server::Delete(std::string_view pattern, HandlerWithContentReader handler)
	{
		delete_handlers_for_content_reader_.push_back(std::make_pair(std::regex(pattern.data()), handler));
		return *this;
	}

	Server& Server::Options(std::string_view pattern, Handler handler)
	{
		options_handlers_.push_back(std::make_pair(std::regex(pattern.data()), handler));
		return *this;
	}

	bool Server::set_mount_point(std::string_view mount_point, std::string_view dir)
	{
		if (detail::is_dir(dir))
		{
			std::string_view mnt = !mount_point.empty() ? mount_point : "/";
			if (!mnt.empty() && mnt[0] == '/')
			{
				base_dirs_.emplace_back(mnt, dir);
				return true;
			}
		}
		return false;
	}

	bool Server::remove_mount_point(std::string_view mount_point)
	{
		for (auto it = base_dirs_.begin(); it != base_dirs_.end(); ++it)
		{
			if (it->first == mount_point)
			{
				base_dirs_.erase(it);
				return true;
			}
		}
		return false;
	}

	void Server::set_file_extension_and_mimetype_mapping(std::string_view ext, std::string_view mime)
	{
		file_extension_and_mimetype_map_[ext.data()] = mime;
	}

	void Server::set_file_request_handler(Handler handler)
	{
		file_request_handler_ = std::move(handler);
	}

	void Server::set_error_handler(Handler handler)
	{
		error_handler_ = std::move(handler);
	}

	void Server::set_logger(Logger logger)
	{
		logger_ = std::move(logger);
	}

	void Server::set_expect_100_continue_handler(Expect100ContinueHandler handler)
	{
		expect_100_continue_handler_ = std::move(handler);
	}

	void Server::set_keep_alive_max_count(size_t count)
	{
		m_Config.KeepAliveMaxCount = count;
	}

	void Server::set_read_timeout(std::chrono::microseconds val)
	{
		m_Config.ReadTimeout = val;
	}

	void Server::set_write_timeout(std::chrono::microseconds val)
	{
		m_Config.WriteTimeout = val;
	}

	void Server::set_idle_interval(std::chrono::microseconds val)
	{
		m_Config.IdleInterval = val;
	}

	void Server::set_payload_max_length(size_t length)
	{
		m_Config.PayloadMaxLength = length;
	}

	bool Server::bind_to_port(std::string_view host, int port, int socket_flags)
	{
		if (bind_internal(host, port, socket_flags) < 0) return false;
		return true;
	}
	int Server::bind_to_any_port(std::string_view host, int socket_flags)
	{
		return bind_internal(host, 0, socket_flags);
	}

	bool Server::listen_after_bind()
	{
		return listen_internal();
	}

	bool Server::listen(std::string_view host, int port, int socket_flags)
	{
		return bind_to_port(host, port, socket_flags) && listen_internal();
	}

	bool Server::is_running() const
	{
		return is_running_;
	}

	void Server::stop()
	{
		if (is_running_)
		{
			assert(svr_sock_ != INVALID_SOCKET);
			std::atomic<socket_t> sock(svr_sock_.exchange(INVALID_SOCKET));
			detail::shutdown_socket(sock);
			detail::close_socket(sock);
		}
	}

	bool Server::parse_request_line(const char* s, Request& req)
	{
		const static std::regex re(
			"(GET|HEAD|POST|PUT|DELETE|CONNECT|OPTIONS|TRACE|PATCH|PRI) "
			"(([^?]+)(?:\\?(.*?))?) (HTTP/1\\.[01])\r\n");

		std::cmatch m;
		if (std::regex_match(s, m, re))
		{
			req.version = std::string(m[5]);
			req.method = std::string(m[1]);
			req.target = std::string(m[2]);
			req.path = detail::decode_url(m[3], false);

			// Parse query text
			auto len = std::distance(m[4].first, m[4].second);
			if (len > 0)
			{
				detail::parse_query_text(m[4], req.params);
			}

			return true;
		}

		return false;
	}

	bool Server::write_response(Stream& strm, bool last_connection, const Request& req, Response& res, std::shared_ptr<Connection> connection, std::string content_type, std::string boundary)
	{
		assert(res.status != -1);

		if (400 <= res.status && error_handler_)
		{
			error_handler_(req, res, connection);
		}

		detail::BufferStream bstrm;
		content_type.clear();
		boundary.clear();

		// Response line
		if (!bstrm.write_format("HTTP/1.1 %d %s\r\n", res.status, detail::status_message(res.status)))
		{
			return false;
		}

		// Headers
		if (last_connection || req.get_header_value("Connection") == "close")
		{
			res.set_header("Connection", "close");
		}

		if (!last_connection && req.get_header_value("Connection") == "Keep-Alive")
		{
			res.set_header("Connection", "Keep-Alive");
		}

		if (!res.has_header("Content-Type") &&
			(!res.body.empty() || res.GetContentLength() > 0))
		{
			res.set_header("Content-Type", "text/plain");
		}

		if (!res.has_header("Accept-Ranges") && req.method == "HEAD")
		{
			res.set_header("Accept-Ranges", "bytes");
		}

		if (req.ranges.size() > 1)
		{
			boundary = detail::make_multipart_data_boundary();

			auto it = res.headers.find("Content-Type");
			if (it != res.headers.end())
			{
				content_type = it->second;
				res.headers.erase(it);
			}

			res.headers.emplace("Content-Type",
				"multipart/byteranges; boundary=" + boundary);
		}

		if (res.body.empty())
		{
			if (res.GetContentLength() > 0)
			{
				size_t length = 0;
				if (req.ranges.empty())
				{
					length = res.GetContentLength();
				}
				else if (req.ranges.size() == 1)
				{
					auto offsets = detail::get_range_offset_and_length(req, res.GetContentLength(), 0);
					auto offset = offsets.first;
					length = offsets.second;
					auto content_range = detail::make_content_range_header_field(offset, length, res.GetContentLength());
					res.set_header("Content-Range", content_range);
				}
				else
				{
					length = detail::get_multipart_ranges_data_length(req, res, boundary, content_type);
				}
				res.set_header("Content-Length", std::to_string(length));
			}
			else
			{
				if (res.GetContentProvider())
				{
					res.set_header("Transfer-Encoding", "chunked");
				}
				else
				{
					res.set_header("Content-Length", "0");
				}
			}
		}
		else
		{
			if (req.ranges.empty())
			{
				;
			}
			else if (req.ranges.size() == 1)
			{
				auto offsets = detail::get_range_offset_and_length(req, res.body.size(), 0);
				auto offset = offsets.first;
				auto length = offsets.second;
				auto content_range = detail::make_content_range_header_field(offset, length, res.body.size());
				res.set_header("Content-Range", content_range);
				res.body = res.body.substr(offset, length);
			}
			else
			{
				res.body =
					detail::make_multipart_ranges_data(req, res, boundary, content_type);
			}

#ifdef CPPHTTPLIB_ZLIB_SUPPORT
			// TODO: 'Accept-Encoding' has gzip, not gzip;q=0
			const auto& encodings = req.get_header_value("Accept-Encoding");
			if (encodings.find("gzip") != std::string::npos && detail::can_compress(res.get_header_value("Content-Type")))
			{
				if (detail::compress(res.body))
				{
					res.set_header("Content-Encoding", "gzip");
				}
			}
#endif

			auto length = std::to_string(res.body.size());
			res.set_header("Content-Length", length);
		}

		if (!detail::write_headers(bstrm, res, Headers()))
		{
			return false;
		}

		// Flush buffer
		auto& data = bstrm.get_buffer();
		strm.write(data);

		return true;
	}

	bool Server::read_content(Stream& strm, Request& req, Response& res)
	{
		MultipartFormDataMap::iterator cur;
		if (read_content_core(
			strm, req, res,
			// Regular
			[&](std::string_view s)
			{
				if (req.body.size() + s.size() > req.body.max_size())
				{
					return false;
				}
				req.body.append(s);
				return true;
			},
			// Multipart
				[&](const MultipartFormData& file)
			{
				cur = req.files.emplace(file.name, file);
				return true;
			},
				[&](std::string_view s)
			{
				auto& content = cur->second.content;
				if (content.size() + s.size() > content.max_size())
				{
					return false;
				}
				content.append(s);
				return true;
			}))
		{
			const auto& content_type = req.get_header_value("Content-Type");
			if (!content_type.find("application/x-www-form-urlencoded"))
			{
				detail::parse_query_text(req.body, req.params);
			}
			return true;
		}
			return false;
	}

	bool Server::read_content_with_content_receiver(Stream& strm, Request& req, Response& res, ContentReceiver receiver, MultipartContentHeader multipart_header, ContentReceiver multipart_receiver)
	{
		return read_content_core(strm, req, res, receiver, multipart_header,
			multipart_receiver);
	}

	bool Server::read_content_core(Stream& strm, Request& req, Response& res, ContentReceiver receiver, MultipartContentHeader mulitpart_header, ContentReceiver multipart_receiver)
	{
		detail::MultipartFormDataParser multipart_form_data_parser;
		ContentReceiver out;

		if (req.is_multipart_form_data())
		{
			const auto& content_type = req.get_header_value("Content-Type");
			std::string boundary;
			if (!detail::parse_multipart_boundary(content_type, boundary))
			{
				res.status = 400;
				return false;
			}

			multipart_form_data_parser.set_boundary(std::move(boundary));
			out = [&](std::string_view s)
			{
				return multipart_form_data_parser.parse(s, multipart_receiver, mulitpart_header);
			};
		}
		else
		{
			out = receiver;
		}

		if (!detail::read_content(strm, req, m_Config.PayloadMaxLength, res.status, Progress(), out, true))
		{
			return false;
		}

		if (req.is_multipart_form_data())
		{
			if (!multipart_form_data_parser.is_valid())
			{
				res.status = 400;
				return false;
			}
		}

		return true;
	}

	bool Server::handle_file_request(Request& req, Response& res, std::shared_ptr<Connection> connection, bool head)
	{
		for (const auto& kv : base_dirs_)
		{
			const auto& mount_point = kv.first;
			const auto& base_dir = kv.second;

			// Prefix match
			if (!req.path.find(mount_point))
			{
				std::string sub_path = "/" + req.path.substr(mount_point.size());
				if (detail::is_valid_path(sub_path))
				{
					auto path = base_dir + sub_path;
					if (path.back() == '/')
					{
						path += "index.html";
					}

					if (detail::is_file(path))
					{
						detail::read_file(path, res.body);
						auto type = detail::find_content_type(path, file_extension_and_mimetype_map_);
						if (type)
						{
							res.set_header("Content-Type", type);
						}
						res.status = 200;
						if (!head && file_request_handler_)
						{
							file_request_handler_(req, res, connection);
						}
						return true;
					}
				}
			}
		}
		return false;
	}

	socket_t Server::create_server_socket(std::string_view host, int port, int socket_flags) const
	{
		return detail::create_socket(
			host, port,
			[](socket_t sock, struct addrinfo& ai) -> bool
			{
				if (::bind(sock, ai.ai_addr, static_cast<socklen_t>(ai.ai_addrlen)))
				{
					return false;
				}
				if (::listen(sock, 5))
				{ // Listen through 5 channels
					return false;
				}
				return true;
			},
			socket_flags);
	}

	int Server::bind_internal(std::string_view host, int port, int socket_flags)
	{
		if (!is_valid())
		{
			return -1;
		}

		svr_sock_ = create_server_socket(host, port, socket_flags);
		if (svr_sock_ == INVALID_SOCKET)
		{
			return -1;
		}

		if (port == 0)
		{
			struct sockaddr_storage addr;
			socklen_t addr_len = sizeof(addr);
			if (getsockname(svr_sock_, reinterpret_cast<struct sockaddr*>(&addr), &addr_len) == -1)
			{
				return -1;
			}
			if (addr.ss_family == AF_INET)
			{
				return ntohs(reinterpret_cast<struct sockaddr_in*>(&addr)->sin_port);
			}
			else if (addr.ss_family == AF_INET6)
			{
				return ntohs(reinterpret_cast<struct sockaddr_in6*>(&addr)->sin6_port);
			}
			else
			{
				return -1;
			}
		}
		else
		{
			return port;
		}
	}

	std::unique_ptr<TaskQueue> Server::new_task_queue(std::unique_ptr<TaskQueue> ptr)
	{
		if (ptr)
			return ptr;
		else
			return std::make_unique<ThreadPool>(std::max<int>(8, std::thread::hardware_concurrency()));
	}

	bool Server::listen_internal()
	{
		auto ret = true;
		is_running_ = true;

		{
			std::shared_ptr<TaskQueue> task_queue(new_task_queue());

			while (svr_sock_ != INVALID_SOCKET)
			{
#ifndef _WIN32
				if (idle_interval_sec_ > 0 || idle_interval_usec_ > 0)
				{
#endif
					auto val = detail::select_read(svr_sock_, m_Config.IdleInterval);
					if (val == 0)
					{ // Timeout
						task_queue->on_idle();
						continue;
					}
#ifndef _WIN32
				}
#endif
				socket_t sock = accept(svr_sock_, nullptr, nullptr);

				if (sock == INVALID_SOCKET)
				{
					if (errno == EMFILE)
					{
						// The per-process limit of open file descriptors has been reached.
						// Try to accept new connections after a short sleep.
						std::this_thread::sleep_for(std::chrono::milliseconds(1));
						continue;
					}
					if (svr_sock_ != INVALID_SOCKET)
					{
						detail::close_socket(svr_sock_);
						ret = false;
					}
					else
					{
						; // The server socket was closed by user.
					}
					break;
				}

				CreateRequestReply(sock, task_queue);
			}

			task_queue->shutdown();
		}

		is_running_ = false;
		return ret;
	}

	bool Server::routing(Request& req, Response& res, std::shared_ptr<Connection> connection, Stream& strm)
	{
		// File handler
		bool is_head_request = req.method == "HEAD";
		if ((req.method == "GET" || is_head_request) && handle_file_request(req, res, connection, is_head_request))
		{
			return true;
		}

		if (detail::expect_content(req))
		{
			// Content reader handler
			{
				ContentReader reader(
					[&](ContentReceiver receiver)
					{
						return read_content_with_content_receiver(strm, req, res, receiver, nullptr, nullptr);
					},
					[&](MultipartContentHeader header, ContentReceiver receiver)
					{
						return read_content_with_content_receiver(strm, req, res, nullptr, header, receiver);
					});

				if (req.method == "POST")
				{
					if (dispatch_request_for_content_reader(req, res, connection, reader, post_handlers_for_content_reader_))
					{
						return true;
					}
				}
				else if (req.method == "PUT")
				{
					if (dispatch_request_for_content_reader(req, res, connection, reader, put_handlers_for_content_reader_))
					{
						return true;
					}
				}
				else if (req.method == "PATCH")
				{
					if (dispatch_request_for_content_reader(req, res, connection, reader, patch_handlers_for_content_reader_))
					{
						return true;
					}
				}
				else if (req.method == "DELETE")
				{
					if (dispatch_request_for_content_reader(req, res, connection, reader, delete_handlers_for_content_reader_))
					{
						return true;
					}
				}
			}

			// Read content into `req.body`
			if (!read_content(strm, req, res))
			{
				return false;
			}
		}

		// Regular handler
		if (req.method == "GET" || req.method == "HEAD")
		{
			return dispatch_request(req, res, connection, get_handlers_);
		}
		else if (req.method == "POST")
		{
			return dispatch_request(req, res, connection, post_handlers_);
		}
		else if (req.method == "PUT")
		{
			return dispatch_request(req, res, connection, put_handlers_);
		}
		else if (req.method == "DELETE")
		{
			return dispatch_request(req, res, connection, delete_handlers_);
		}
		else if (req.method == "OPTIONS")
		{
			return dispatch_request(req, res, connection, options_handlers_);
		}
		else if (req.method == "PATCH")
		{
			return dispatch_request(req, res, connection, patch_handlers_);
		}

		res.status = 400;
		return false;
	}

	bool Server::dispatch_request(Request& req, Response& res, std::shared_ptr<Connection> connection, Handlers& handlers)
	{
		try
		{
			for (const auto& x : handlers)
			{
				const auto& pattern = x.first;
				const auto& handler = x.second;

				if (std::regex_match(req.path, req.matches, pattern))
				{
					handler(req, res, connection);
					return true;
				}
			}
		}
		catch (const std::exception& ex)
		{
			res.status = 500;
			res.set_header("EXCEPTION_WHAT", ex.what());
		}
		catch (...)
		{
			res.status = 500;
			res.set_header("EXCEPTION_WHAT", "UNKNOWN");
		}
		return false;
	}

	bool Server::dispatch_request_for_content_reader(Request& req, Response& res, std::shared_ptr<Connection> connection, ContentReader content_reader, HandlersForContentReader& handlers)
	{
		for (const auto& x : handlers)
		{
			const auto& pattern = x.first;
			const auto& handler = x.second;

			if (std::regex_match(req.path, req.matches, pattern))
			{
				handler(req, res, connection, content_reader);
				return true;
			}
		}
		return false;
	}

	bool Server::process_request(Stream& strm, Request& req, Response& res, std::shared_ptr<Connection> connection, bool last_connection, bool& connection_close, const std::function<void(Request&)>& setup_request)
	{
		std::array<char, 2048> buf{};

		detail::stream_line_reader line_reader(strm, buf.data(), buf.size());

		// Connection has been closed on client
		if (!line_reader.getline())
		{
			return false;
		}

		res.version = "HTTP/1.1";

		// Check if the request URI doesn't exceed the limit
		if (line_reader.size() > 2048)
		{
			Headers dummy;
			detail::read_headers(strm, dummy);
			res.status = 414;
			return true;
		}

		// Request line and headers
		if (!parse_request_line(line_reader.ptr(), req) || !detail::read_headers(strm, req.headers))
		{
			res.status = 400;
			return true;
		}

		if (req.get_header_value("Connection") == "close")
		{
			connection_close = true;
		}

		if (req.version == "HTTP/1.0" &&
			req.get_header_value("Connection") != "Keep-Alive")
		{
			connection_close = true;
		}

		strm.get_remote_ip_and_port(req.remote_addr, req.remote_port);
		req.set_header("REMOTE_ADDR", req.remote_addr);
		req.set_header("REMOTE_PORT", std::to_string(req.remote_port));

		if (req.has_header("Range"))
		{
			const auto& range_header_value = req.get_header_value("Range");
			if (!detail::parse_range_header(range_header_value, req.ranges))
			{
				// TODO: error
			}
		}

		if (setup_request)
		{
			setup_request(req);
		}

		if (req.get_header_value("Expect") == "100-continue")
		{
			auto status = 100;
			if (expect_100_continue_handler_)
			{
				status = expect_100_continue_handler_(req, res, connection);
			}
			switch (status)
			{
			case 100:
			case 417:
				strm.write_format("HTTP/1.1 %d %s\r\n\r\n", status, detail::status_message(status));
				break;
			default: return true;
			}
		}

		// Rounting
		if (routing(req, res, connection, strm))
		{
			if (res.status == -1)
			{
				res.status = req.ranges.empty() ? 200 : 206;
			}
		}
		else
		{
			if (res.status == -1)
			{
				res.status = 404;
			}
		}

		return true;
	}

	bool Server::is_valid() const
	{
		return true;
	}






	void Server::Connection::Create(Server& server, socket_t socket, std::shared_ptr<TaskQueue> threadPool)
	{
		auto sptr = std::make_shared<Server::Connection>(server, socket, threadPool);
		Server::Connection::Step(sptr, true);
	}

	void Server::CreateRequestReply(socket_t socket, std::shared_ptr<TaskQueue> threadPool)
	{
		Server::Connection::Create(*this, socket, threadPool);
	}

	Server::Connection::Connection(Server& server, socket_t sock, std::shared_ptr<TaskQueue> threadPool) :
		m_Server(server),
		m_Socket(sock),
		m_ThreadPool(threadPool),
		m_ProcessCount(server.m_Config.KeepAliveMaxCount)
	{
		assert(m_ProcessCount > 0);
	}
	Server::Connection::~Connection()
	{
		m_Stream.reset();
		detail::close_socket(m_Socket);
	}

	std::unique_ptr<Stream> Server::Connection::CreateStream()
	{
		return std::make_unique<detail::SocketStream>(m_Socket, m_Server.m_Config.ReadTimeout, m_Server.m_Config.WriteTimeout);
	}

	bool Server::Connection::Step(std::shared_ptr<Connection> handler, bool EnqueueNextStep)
	{
		if (handler)
		{
			std::unique_lock<std::mutex> lock(handler->m_StepMutex);
			handler->m_UsingThreadPool = EnqueueNextStep;
			handler->p_Step(handler);

			if (handler->m_NextStep != NextStep::Quit &&
				handler->m_Server.svr_sock_ != INVALID_SOCKET)
			{
				if (handler->m_UsingThreadPool)
				{
					if (auto pool = handler->m_ThreadPool.lock())
						pool->enqueue(std::bind(&Server::Connection::Step, handler, true));
				}
				return true;
			}
		}

		return false;
	}

	bool Server::Connection::GetUsingThreadPool() const { return m_UsingThreadPool; }
	void Server::Connection::SetUsingThreadPool(bool val) { m_UsingThreadPool = val; }

	Request& Server::Connection::GetRequest() { return m_Request; }
	Response& Server::Connection::GetResponse() { return m_Response; }

	void Server::Connection::p_Step(std::shared_ptr<Connection> self)
	{
		if (m_NextStep == NextStep::AcceptRequest)
		{
			if (p_AcceptRequest())
				m_NextStep = NextStep::ProcessRequest;
			else
				m_NextStep = NextStep::Quit;
		}

		if (m_NextStep == NextStep::ProcessRequest)
			m_NextStep = p_ProcessRequest(self);

		if (m_NextStep == NextStep::SendResponseHeader)
			m_NextStep = p_SendResponseHeader(self);

		if (m_NextStep == NextStep::SendResponseBody)
			m_NextStep = p_SendResponseBody();

		if (m_NextStep == NextStep::SendResponseBodyWithProvider)
			m_NextStep = p_SendResponseBodyWithProvider(self);


		if (m_NextStep == NextStep::ResponseComplete)
		{
			p_OnComplete();

			if (m_Server.logger_)
				m_Server.logger_(m_Request, m_Response);

			m_Request = Request();
			m_Response = Response();

			if (m_ProcessCount > 0)
				m_NextStep = NextStep::ProcessRequest;
			else
				m_NextStep = NextStep::Quit;
		}
		else if (m_NextStep == NextStep::Error)
		{
			p_OnError();
			m_NextStep = NextStep::Quit;
		}
	}

	bool Server::Connection::p_AcceptRequest()
	{
		return true;
	}
	Server::Connection::NextStep Server::Connection::p_ProcessRequest(std::shared_ptr<Connection> self)
	{
		--m_ProcessCount;

		if (!m_Stream)
			m_Stream = CreateStream();

		bool connection_close = false;
		if (!m_Server.process_request(*m_Stream, m_Request, m_Response, self, m_ProcessCount == 0, connection_close, m_SetupRequest) || connection_close)
			return NextStep::Error;

		return NextStep::SendResponseHeader;
	}
	Server::Connection::NextStep Server::Connection::p_SendResponseHeader(std::shared_ptr<Connection> self)
	{
		if (!m_Server.write_response(*m_Stream, m_ProcessCount == 0, m_Request, m_Response, self, m_Boundary, m_ContentType))
			return Server::Connection::NextStep::Error;

		return Server::Connection::NextStep::SendResponseBody;
	}
	Server::Connection::NextStep Server::Connection::p_SendResponseBody()
	{
		if (m_Request.method != "HEAD")
		{
			if (!m_Response.body.empty())
			{
				if (!m_Stream->write(m_Response.body))
					return Server::Connection::NextStep::Error;
			}
			else if (m_Response.GetContentProvider())
				return Server::Connection::NextStep::SendResponseBodyWithProvider;
		}

		return Server::Connection::NextStep::ResponseComplete;
	}
	Server::Connection::NextStep Server::Connection::p_SendResponseBodyWithProvider(std::shared_ptr<Connection> self)
	{
		if (m_Response.GetContentProvider())
		{
			if (m_Response.GetContentLength())
			{
				if (m_Request.ranges.empty())
				{
					if (detail::write_content(*m_Stream, m_Response.GetContentProvider(), 0, m_Response.GetContentLength()) < 0)
						return Server::Connection::NextStep::Error;
				}
				else if (m_Request.ranges.size() == 1)
				{
					auto offsets = detail::get_range_offset_and_length(m_Request, m_Response.GetContentLength(), 0);
					auto offset = offsets.first;
					auto length = offsets.second;
					if (detail::write_content(*m_Stream, m_Response.GetContentProvider(), offset, length) < 0)
						return Server::Connection::NextStep::Error;
				}
				else
				{
					if (!detail::write_multipart_ranges_data(*m_Stream, m_Request, m_Response, m_Boundary, m_ContentType))
						return Server::Connection::NextStep::Error;
				}
			}
			else
			{
				if (!detail::write_content_chunked(*m_Stream, m_Response.GetContentProvider(), m_ChunkCounters))
					return Server::Connection::NextStep::Error;

				if (m_ChunkCounters.data_available)
					return Server::Connection::NextStep::SendResponseBodyWithProvider;
				else
					return Server::Connection::NextStep::ResponseComplete;
			}
		}

		return Server::Connection::NextStep::Error;
	}
	void Server::Connection::p_OnComplete() {}
	void Server::Connection::p_OnError() {}
}