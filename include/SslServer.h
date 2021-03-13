//
// Copyright (c) 2020 Yuji Hirose, 2021 Russell Trahan. All rights reserved. 
// Portions of this project have been copied from cpp-httplib by Yuji Hirose and modified by Russell Trahan.
//  
// MIT License
//

#pragma once

#include "httplib.h"
#include "Server.h"

namespace httplib
{
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
	class SSLServer : public Server
	{
	public:
		class SslConnection : public Server::Connection
		{
		public:
			static void Create(SSLServer& server, socket_t socket, std::shared_ptr<TaskQueue> threadPool);

			SslConnection(SSLServer& server, socket_t socket, std::shared_ptr<TaskQueue> threadPool);
			~SslConnection();

		protected:
			std::unique_ptr<Stream> CreateStream() override;

			bool p_AcceptRequest() override;
			void p_OnError() override;

		private:
			SSLServer& m_SslServer;
			SSL* m_Ssl = nullptr;
			bool m_SslActive = false;
		};
		void CreateRequestReply(socket_t socket, std::shared_ptr<TaskQueue> threadPool) override;

		CPPHTTPLIBEXPORT SSLServer(const char* cert_path, const char* private_key_path,
			const char* client_ca_cert_file_path = nullptr,
			const char* client_ca_cert_dir_path = nullptr);

		CPPHTTPLIBEXPORT SSLServer(X509* cert, EVP_PKEY* private_key, X509_STORE* client_ca_cert_store = nullptr);

		~SSLServer() override;

		bool is_valid() const override;

	private:
		SSL_CTX* ctx_;
		std::mutex ctx_mutex_;
	};
#endif
}