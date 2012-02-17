#ifndef SSL_SERVER_H
#define SSL_SERVER_H

#include <openssl/ssl.h>

class ssl_server
{
	public:
		explicit ssl_server( unsigned short port, unsigned int max_conns );
		~ssl_server();

		bool init();
		bool run();

	private:
		bool init_dh();
		bool init_rsa();
	
		bool handshake( SSL *ssl_p );
		bool handle_op( SSL *ssl_p );

		SSL_CTX *context_ptr;
		DH *dh_ptr;
		RSA *rsa_priv;
		RSA *rsa_pub;

		// client keys
		RSA *ci_pub;
		RSA *cj_pub;

		unsigned short port;
		int sock;
		unsigned int max_conns;
};

#endif
