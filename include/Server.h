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
	class Server
	{
	public:
		struct Config
		{
			size_t KeepAliveMaxCount = 5;
			std::chrono::microseconds KeepAliveTimeout = 5s;
			std::chrono::microseconds ConnectionTimeout = 300s;
			std::chrono::microseconds ReadTimeout = 5s;
			std::chrono::microseconds WriteTimeout = 5s;
			std::chrono::microseconds IdleInterval = 10s;
			size_t PayloadMaxLength = std::numeric_limits<size_t>::max();
		};

		class Connection
		{
		public:
			static void Create(Server& server, socket_t socket, std::shared_ptr<TaskQueue> threadPool);

			Connection(Server& server, socket_t socket, std::shared_ptr<TaskQueue> threadPool);
			CPPHTTPLIBEXPORT virtual ~Connection();

			//! Executes the next operation on this request.
			//! \param handler The request handler to execute
			//! \param EnqueueNextStep If true the following step is enqueued in the server's thread pool. If false the user must manually call Step again.
			//! \return Returns whether Step can be called again without being a no-op. A no-op would be caused by the request being completed or closed due to an error.
			CPPHTTPLIBEXPORT static bool Step(std::shared_ptr<Connection> handler, bool EnqueueNextStep);

			//! Gets whether the current call to Step will call Step again using the server's thread pool if needed
			CPPHTTPLIBEXPORT bool GetUsingThreadPool() const;
			//! Sets whether the current call to Step will call Step again using the server's thread pool if needed. If set to false, be sure to execute Step manually again at some time in the future to complete the request.
			CPPHTTPLIBEXPORT void SetUsingThreadPool(bool val);

			CPPHTTPLIBEXPORT Request& GetRequest();
			CPPHTTPLIBEXPORT Response& GetResponse();

		protected:
			bool m_UsingThreadPool = false;
			std::function<void(Request&)> m_SetupRequest;

			virtual std::unique_ptr<Stream> CreateStream();
			virtual bool p_AcceptRequest();
			virtual void p_OnComplete();
			virtual void p_OnError();

			socket_t m_Socket = 0;

		private:
			std::mutex m_StepMutex;
			void p_Step(std::shared_ptr<Connection> self);

			enum class NextStep
			{
				Quit,
				AcceptRequest,
				ProcessRequest,
				SendResponseHeader,
				SendResponseBody,
				SendResponseBodyWithProvider,
				ResponseComplete,
				Error
			};

			NextStep p_ProcessRequest(std::shared_ptr<Connection> self);
			NextStep p_SendResponseHeader(std::shared_ptr<Connection> self);
			NextStep p_SendResponseBody();
			NextStep p_SendResponseBodyWithProvider(std::shared_ptr<Connection> self);

			NextStep m_NextStep = NextStep::AcceptRequest;

			Server& m_Server;
			std::unique_ptr<Stream> m_Stream;

			int64_t m_ProcessCount = 0;
			std::weak_ptr<TaskQueue> m_ThreadPool;

			Request m_Request;
			Response m_Response;

			std::string m_Boundary;
			std::string m_ContentType;

			ChunkedContentCounters m_ChunkCounters;
		};
		virtual void CreateRequestReply(socket_t socket, std::shared_ptr<TaskQueue> threadPool);

		using Handler = std::function<void(const Request&, Response&, std::shared_ptr<Connection>)>;
		using HandlerWithContentReader = std::function<void(const Request&, Response&, std::shared_ptr<Connection>, const ContentReader& content_reader)>;
		using Expect100ContinueHandler = std::function<int(const Request&, Response&, std::shared_ptr<Connection>)>;

		CPPHTTPLIBEXPORT Server();
		CPPHTTPLIBEXPORT virtual ~Server();

		virtual bool is_valid() const;

		CPPHTTPLIBEXPORT Server& Get(std::string_view pattern, Handler handler);
		CPPHTTPLIBEXPORT Server& Post(std::string_view pattern, Handler handler);
		CPPHTTPLIBEXPORT Server& Post(std::string_view pattern, HandlerWithContentReader handler);
		CPPHTTPLIBEXPORT Server& Put(std::string_view pattern, Handler handler);
		CPPHTTPLIBEXPORT Server& Put(std::string_view pattern, HandlerWithContentReader handler);
		CPPHTTPLIBEXPORT Server& Patch(std::string_view pattern, Handler handler);
		CPPHTTPLIBEXPORT Server& Patch(std::string_view pattern, HandlerWithContentReader handler);
		CPPHTTPLIBEXPORT Server& Delete(std::string_view pattern, Handler handler);
		CPPHTTPLIBEXPORT Server& Delete(std::string_view pattern, HandlerWithContentReader handler);
		CPPHTTPLIBEXPORT Server& Options(std::string_view pattern, Handler handler);

		CPPHTTPLIBEXPORT bool set_mount_point(std::string_view mount_point, std::string_view dir);
		CPPHTTPLIBEXPORT bool remove_mount_point(std::string_view mount_point);
		CPPHTTPLIBEXPORT void set_file_extension_and_mimetype_mapping(std::string_view ext, std::string_view mime);
		CPPHTTPLIBEXPORT void set_file_request_handler(Handler handler);

		CPPHTTPLIBEXPORT void set_error_handler(Handler handler);
		CPPHTTPLIBEXPORT void set_logger(Logger logger);

		CPPHTTPLIBEXPORT void set_expect_100_continue_handler(Expect100ContinueHandler handler);

		CPPHTTPLIBEXPORT void set_keep_alive_max_count(size_t count);
		CPPHTTPLIBEXPORT void set_read_timeout(std::chrono::microseconds val);
		CPPHTTPLIBEXPORT void set_write_timeout(std::chrono::microseconds val);
		CPPHTTPLIBEXPORT void set_idle_interval(std::chrono::microseconds val);

		CPPHTTPLIBEXPORT void set_payload_max_length(size_t length);

		CPPHTTPLIBEXPORT bool bind_to_port(std::string_view host, int port, int socket_flags = 0);
		CPPHTTPLIBEXPORT int bind_to_any_port(std::string_view host, int socket_flags = 0);
		CPPHTTPLIBEXPORT bool listen_after_bind();

		CPPHTTPLIBEXPORT bool listen(std::string_view host, int port, int socket_flags = 0);

		CPPHTTPLIBEXPORT bool is_running() const;
		CPPHTTPLIBEXPORT void stop();

		virtual std::unique_ptr<TaskQueue> new_task_queue(std::unique_ptr<TaskQueue> queue = nullptr);

	protected:
		bool process_request(Stream& strm, Request& req, Response& res, std::shared_ptr<Connection> connection, bool& connection_close, const std::function<void(Request&)>& setup_request);

		Config m_Config;

	private:
		using Handlers = std::vector<std::pair<std::regex, Handler>>;
		using HandlersForContentReader = std::vector<std::pair<std::regex, HandlerWithContentReader>>;

		socket_t create_server_socket(std::string_view host, int port, int socket_flags) const;
		int bind_internal(std::string_view host, int port, int socket_flags);
		bool listen_internal();

		bool routing(Request& req, Response& res, std::shared_ptr<Connection> connection, Stream& strm);
		bool handle_file_request(Request& req, Response& res, std::shared_ptr<Connection> connection, bool head = false);
		bool dispatch_request(Request& req, Response& res, std::shared_ptr<Connection> connection, Handlers& handlers);
		bool dispatch_request_for_content_reader(Request& req, Response& res, std::shared_ptr<Connection> connection, ContentReader content_reader, HandlersForContentReader& handlers);

		bool parse_request_line(const char* s, Request& req);
		bool write_response(Stream& strm, bool last_connection, const Request& req, Response& res, std::shared_ptr<Connection> connection, std::string content_type, std::string boundary);
		bool read_content(Stream& strm, Request& req, Response& res);
		bool read_content_with_content_receiver(Stream& strm, Request& req, Response& res, ContentReceiver receiver, MultipartContentHeader multipart_header, ContentReceiver multipart_receiver);
		bool read_content_core(Stream& strm, Request& req, Response& res, ContentReceiver receiver, MultipartContentHeader mulitpart_header, ContentReceiver multipart_receiver);

		std::atomic<bool> is_running_;
		std::atomic<socket_t> svr_sock_;
		std::vector<std::pair<std::string, std::string>> base_dirs_;
		std::map<std::string, std::string> file_extension_and_mimetype_map_;
		Handler file_request_handler_;
		Handlers get_handlers_;
		Handlers post_handlers_;
		HandlersForContentReader post_handlers_for_content_reader_;
		Handlers put_handlers_;
		HandlersForContentReader put_handlers_for_content_reader_;
		Handlers patch_handlers_;
		HandlersForContentReader patch_handlers_for_content_reader_;
		Handlers delete_handlers_;
		HandlersForContentReader delete_handlers_for_content_reader_;
		Handlers options_handlers_;
		Handler error_handler_;
		Logger logger_;
		Expect100ContinueHandler expect_100_continue_handler_;
	};
}