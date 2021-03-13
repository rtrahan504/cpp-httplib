//
// Copyright (c) 2020 Yuji Hirose, 2021 Russell Trahan. All rights reserved. 
// Portions of this project have been copied from cpp-httplib by Yuji Hirose and modified by Russell Trahan.
//  
// MIT License
//

#include "SslServer.h"
#include "Utility.h"

namespace httplib
{
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT

	void SSLServer::SslConnection::Create(SSLServer& server, socket_t socket, std::shared_ptr<TaskQueue> threadPool)
	{
		auto sptr = std::make_shared<SSLServer::SslConnection>(server, socket, threadPool);
		SSLServer::SslConnection::Step(sptr, true);
	}

	void SSLServer::CreateRequestReply(socket_t socket, std::shared_ptr<TaskQueue> threadPool)
	{
		SSLServer::SslConnection::Create(*this, socket, threadPool);
	}

	SSLServer::SslConnection::SslConnection(SSLServer& server, socket_t sock, std::shared_ptr<TaskQueue> threadPool) :
		Connection(server, sock, threadPool),
		m_SslServer(server)
	{
		{
			std::lock_guard<std::mutex> guard(m_SslServer.ctx_mutex_);
			m_Ssl = SSL_new(m_SslServer.ctx_);
		}
		if (!m_Ssl)
		{
			detail::close_socket(sock);
			return;
		}

		m_SetupRequest = [this](Request& req) { req.ssl = this->m_Ssl; };

		auto bio = BIO_new_socket(static_cast<int>(sock), BIO_NOCLOSE);
		SSL_set_bio(m_Ssl, bio, bio);

		{
			SSL_shutdown(m_Ssl);
			{
				std::lock_guard<std::mutex> guard(m_SslServer.ctx_mutex_);
				SSL_free(m_Ssl);
			}
			m_Ssl = nullptr;

			detail::close_socket(sock);
			return;
		}

	}
	SSLServer::SslConnection::~SslConnection()
	{
		if (m_SslActive)
			SSL_shutdown(m_Ssl);

		{
			std::lock_guard<std::mutex> guard(m_SslServer.ctx_mutex_);
			SSL_free(m_Ssl);
			m_Ssl = nullptr;
		}
	}

	bool SSLServer::SslConnection::p_AcceptRequest()
	{
		if (SSL_accept(m_Ssl) == 1)
		{
			m_SslActive = true;
			return true;
		}
		else
			return false;
	}
	void SSLServer::SslConnection::p_OnError()
	{
		m_SslActive = false;
	}

	std::unique_ptr<Stream> SSLServer::SslConnection::CreateStream()
	{
		return std::make_unique<detail::SSLSocketStream>(m_Socket, m_Ssl, m_SslServer.m_Config.ReadTimeout, m_SslServer.m_Config.WriteTimeout);
	}

	namespace detail
	{
		/*
		template <typename U, typename V, typename T>
		void process_and_close_socket_ssl(
			bool is_client_request, socket_t sock, size_t keep_alive_max_count,
			time_t read_timeout_sec, time_t read_timeout_usec, time_t write_timeout_sec,
			time_t write_timeout_usec, SSL_CTX* ctx, std::mutex& ctx_mutex,
			U SSL_connect_or_accept, V setup, T callback)
		{

			auto ret = false;

			if (SSL_connect_or_accept(ssl) == 1)
			{
				if (keep_alive_max_count > 1)
				{
					auto count = keep_alive_max_count;
					while (count > 0 &&
						(is_client_request ||
							select_read(sock, CPPHTTPLIB_KEEPALIVE_TIMEOUT_SECOND,
								CPPHTTPLIB_KEEPALIVE_TIMEOUT_USECOND) > 0))
					{
						SSLSocketStream strm(sock, ssl, read_timeout_sec, read_timeout_usec,
							write_timeout_sec, write_timeout_usec);
						auto last_connection = count == 1;
						auto connection_close = false;

						ret = callback(ssl, strm, last_connection, connection_close);
						if (!ret || connection_close)
						{
							break;
						}

						count--;
					}
				}
				else
				{
					SSLSocketStream strm(sock, ssl, read_timeout_sec, read_timeout_usec,
						write_timeout_sec, write_timeout_usec);
					auto dummy_connection_close = false;
					ret = callback(ssl, strm, true, dummy_connection_close);
				}
			}

			if (ret)
			{
				SSL_shutdown(ssl); // shutdown only if not already closed by remote
			}
		}
		*/

#if OPENSSL_VERSION_NUMBER < 0x10100000L
		static std::shared_ptr<std::vector<std::mutex>> openSSL_locks_;

		class SSLThreadLocks
		{
		public:
			SSLThreadLocks()
			{
				openSSL_locks_ =
					std::make_shared<std::vector<std::mutex>>(CRYPTO_num_locks());
				CRYPTO_set_locking_callback(locking_callback);
			}

			~SSLThreadLocks()
			{
				CRYPTO_set_locking_callback(nullptr);
			}

		private:
			static void locking_callback(int mode, int type, const char* /*file*/,
				int /*line*/)
			{
				auto& lk = (*openSSL_locks_)[static_cast<size_t>(type)];
				if (mode & CRYPTO_LOCK)
				{
					lk.lock();
				}
				else
				{
					lk.unlock();
				}
			}
		};

#endif

		class SSLInit
		{
		public:
			SSLInit()
			{
#if OPENSSL_VERSION_NUMBER < 0x1010001fL
				SSL_load_error_strings();
				SSL_library_init();
#else
				OPENSSL_init_ssl(
					OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);
#endif
			}

			~SSLInit()
			{
#if OPENSSL_VERSION_NUMBER < 0x1010001fL
				ERR_free_strings();
#endif
			}

		private:
#if OPENSSL_VERSION_NUMBER < 0x10100000L
			SSLThreadLocks thread_init_;
#endif
		};

		// SSL socket stream implementation
		SSLSocketStream::SSLSocketStream(socket_t sock, SSL* ssl, std::chrono::microseconds readTimeout, std::chrono::microseconds writeTimeout)
			: sock_(sock), ssl_(ssl), 
			m_ReadTimeout(readTimeout),
			m_WriteTimeout(writeTimeout)
		{
		}

		SSLSocketStream::~SSLSocketStream()
		{
		}

		bool SSLSocketStream::is_readable() const
		{
			return detail::select_read(sock_, m_ReadTimeout) > 0;
		}

		bool SSLSocketStream::is_writable() const
		{
			return detail::select_write(sock_, m_WriteTimeout) >
				0;
		}

		ssize_t SSLSocketStream::read(char* ptr, size_t size)
		{
			if (SSL_pending(ssl_) > 0 ||
				select_read(sock_, m_ReadTimeout) > 0)
			{
				return SSL_read(ssl_, ptr, static_cast<int>(size));
			}
			return -1;
		}

		ssize_t SSLSocketStream::write(std::string_view s)
		{
			if (is_writable())
			{
				return SSL_write(ssl_, s.data(), static_cast<int>(s.size()));
			}
			return -1;
		}

		void SSLSocketStream::get_remote_ip_and_port(std::string& ip,
			int& port) const
		{
			detail::get_remote_ip_and_port(sock_, ip, port);
		}

		static SSLInit sslinit_;

	} // namespace detail

	// SSL HTTP server implementation
	SSLServer::SSLServer(const char* cert_path, const char* private_key_path,
		const char* client_ca_cert_file_path,
		const char* client_ca_cert_dir_path)
	{
		ctx_ = SSL_CTX_new(SSLv23_server_method());

		if (ctx_)
		{
			SSL_CTX_set_options(ctx_,
				SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 |
				SSL_OP_NO_COMPRESSION |
				SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION);

			// auto ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
			// SSL_CTX_set_tmp_ecdh(ctx_, ecdh);
			// EC_KEY_free(ecdh);

			if (SSL_CTX_use_certificate_chain_file(ctx_, cert_path) != 1 ||
				SSL_CTX_use_PrivateKey_file(ctx_, private_key_path, SSL_FILETYPE_PEM) !=
				1)
			{
				SSL_CTX_free(ctx_);
				ctx_ = nullptr;
			}
			else if (client_ca_cert_file_path || client_ca_cert_dir_path)
			{
				// if (client_ca_cert_file_path)
				// {
				//   auto list = SSL_load_client_CA_file(client_ca_cert_file_path);
				//   SSL_CTX_set_client_CA_list(ctx_, list);
				// }

				SSL_CTX_load_verify_locations(ctx_, client_ca_cert_file_path,
					client_ca_cert_dir_path);

				SSL_CTX_set_verify(
					ctx_,
					SSL_VERIFY_PEER |
					SSL_VERIFY_FAIL_IF_NO_PEER_CERT, // SSL_VERIFY_CLIENT_ONCE,
					nullptr);
			}
		}
	}

	SSLServer::SSLServer(X509* cert, EVP_PKEY* private_key,
		X509_STORE* client_ca_cert_store)
	{
		ctx_ = SSL_CTX_new(SSLv23_server_method());

		if (ctx_)
		{
			SSL_CTX_set_options(ctx_,
				SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 |
				SSL_OP_NO_COMPRESSION |
				SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION);

			if (SSL_CTX_use_certificate(ctx_, cert) != 1 ||
				SSL_CTX_use_PrivateKey(ctx_, private_key) != 1)
			{
				SSL_CTX_free(ctx_);
				ctx_ = nullptr;
			}
			else if (client_ca_cert_store)
			{

				SSL_CTX_set_cert_store(ctx_, client_ca_cert_store);

				SSL_CTX_set_verify(
					ctx_,
					SSL_VERIFY_PEER |
					SSL_VERIFY_FAIL_IF_NO_PEER_CERT, // SSL_VERIFY_CLIENT_ONCE,
					nullptr);
			}
		}
	}

	SSLServer::~SSLServer()
	{
		if (ctx_)
		{
			SSL_CTX_free(ctx_);
		}
	}

	bool SSLServer::is_valid() const
	{
		return ctx_;
	}
#endif
}