#ifndef SSL_CLIENT_H
#define SSL_CLIENT_H

#include <openssl/ssl.h>

class ssl_client
{
	public:
		explicit ssl_client();
		~ssl_client();
		void destroy();
		
		bool init_rsa();
		bool init();
		bool conn( const char* sip, unsigned short port );
		void store( const char* f );
		void retrieve( const char *f );

	private:
		bool handshake();

		RSA *rsa_pub;
		RSA *rsa_priv;

		RSA *server_pub;
		RSA *friend_pub;
		SSL_CTX *context_ptr;
		int sock;
		SSL *ssl_ptr;
};

#endif
