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
		
		unsigned short port;
		unsigned int max_conns;
		SSL_CTX *context_ptr;
		RSA *rsa_pub;
		RSA *rsa_priv;
		DH *dh_ptr;
		// client keys
		RSA *ci_pub;
		RSA *cj_pub;
		int sock;
};

#endif
