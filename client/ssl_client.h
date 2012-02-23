#ifndef SSL_CLIENT_H
#define SSL_CLIENT_H

#include <openssl/ssl.h>

class ssl_client
{
	public:
		ssl_client();
		~ssl_client();
		void destroy();
		
		bool init_rsa();
		bool init();
		bool conn( const char* sip, unsigned short port );
		void store( const char* f );
		void retrieve( const char *f );

	private:
		bool handshake();
		SSL *ssl_ptr;
		SSL_CTX *context_ptr;
		RSA *rsa_pub;
		RSA *rsa_priv;
		RSA *server_pub;
		RSA *friend_pub;
		int sock;
};

#endif
