#include <openssl/err.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <iostream>
#include "ssl_server.h"
#include <cstdio>
#include <fstream>

ssl_server::ssl_server( unsigned short port, unsigned int max_conns )
	:	port(port),
		max_conns( max_conns ),
		context_ptr(0),
		rsa_pub(0),
		rsa_priv(0),
		dh_ptr(0),
		ci_pub(0),
		cj_pub(0)
{
}

ssl_server::~ssl_server()
{
	if( dh_ptr )
		DH_free( dh_ptr );
	if( rsa_pub )
		RSA_free( rsa_pub );
	if( rsa_priv )
		RSA_free( rsa_priv );
	if( ci_pub )
		RSA_free( ci_pub );
	if( cj_pub )
		RSA_free( cj_pub );
	ERR_free_strings();
	EVP_cleanup();
	if( context_ptr )
		SSL_CTX_free( context_ptr );
}

bool ssl_server::init_dh()
{
	dh_ptr = DH_new();
	if( !dh_ptr )
	{
		std::cerr << "DH failed to initialize" << std::endl;
		return false;
	}

	if( !DH_generate_parameters_ex( dh_ptr, 128, DH_GENERATOR_2, 0 ) )
	{
		std::cerr << "DH failed to generate parameters" << std::endl;
		return false;
	}

	int codes = 0;
	if( !DH_check( dh_ptr, &codes ) )
	{
		std::cerr << "DH failed to check" << std::endl;
		return false;
	}

	if( !DH_generate_key( dh_ptr ) )
	{
		std::cerr << "DH failed to generate key" << std::endl;
		return false;
	}
	SSL_CTX_set_tmp_dh( context_ptr, dh_ptr );

	return true;
}

bool ssl_server::init_rsa()
{
	rsa_pub = PEM_read_RSA_PUBKEY( fopen( "keys/server.pub", "r" ), 0, 0, 0 );
	if( !rsa_pub )
	{
		std::cout << "Public key failed" << std::endl;
		return false;
	}

	rsa_priv = PEM_read_RSAPrivateKey( fopen( "keys/server.priv", "r" ), 0, 0, 0 );
	if( !rsa_priv )
	{
		std::cout << "Private key failed" << std::endl;
		return false;
	}

	ci_pub = PEM_read_RSA_PUBKEY( fopen( "keys/ci.pub", "r" ), 0, 0, 0 );
	if( !ci_pub )
	{
		std::cout << "Ci Public key failed" << std::endl;
		return false;
	}

	cj_pub = PEM_read_RSA_PUBKEY( fopen( "keys/cj.pub", "r" ), 0, 0, 0 );
	if( !cj_pub )
	{
		std::cout << "Cj Public key failed" << std::endl;
		return false;
	}

	return true;
}

bool ssl_server::init()
{
	// SETUP SSL
	SSL_library_init();
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();

	context_ptr = SSL_CTX_new( SSLv23_server_method() );
	if( !context_ptr )
	{
		ERR_print_errors_fp( stderr );
		return false;
	}
	
	SSL_CTX_set_verify( context_ptr, SSL_VERIFY_NONE, 0 );
	SSL_CTX_set_cipher_list( context_ptr, "ADH-AES256-SHA" );

	// Add dh keys to context
	if( !init_dh() )
	{
		std::cout << "Failed to init dh key" << std::endl;
		return false;
	}

	if( !init_rsa() )
	{
		std::cerr << "Failed to init rsa keys" << std::endl;
		return false;
	}

	// BIND TCP SOCKET
	// Create socket for incoming connections
	if( ( sock = socket( AF_INET, SOCK_STREAM, 0 ) ) < 0 )
	{
		std::cerr << "Failed to create socket" << std::endl;
		return false;
	}

	// Construct local address structure
	struct sockaddr_in iaddr;
	memset( &iaddr, 0, sizeof(iaddr) );
	iaddr.sin_family = AF_INET;
	iaddr.sin_port = htons( port );
	iaddr.sin_addr.s_addr = INADDR_ANY;

	// Bind name to socket
	if( bind( sock, reinterpret_cast<struct sockaddr*>(&iaddr), sizeof(iaddr) ) != 0 )
	{
		std::cerr << "Failed to open socket" << std::endl;
		return false;
	}

	// Mark socket as accepting connections	
	if( listen( sock, max_conns ) != 0 )
	{
		std::cout << "Failed to start listening for connections" << std::endl;
		return false;
	}

	return true;
}

bool ssl_server::handshake( SSL *sp )
{
	/*
 	 *	RECV ENC PRNG CHALLENGE ( THE KEYS ARE 1024 bits = 128 bytes
 	 */
	// Magic numbers pre agreed upon 64
	unsigned char *enc_chal = new unsigned char[128];

	SSL_read( sp, enc_chal, 128 );

	unsigned char dec_chal[64] = {0};
	if( RSA_private_decrypt( 128, enc_chal, dec_chal, rsa_priv, RSA_PKCS1_PADDING ) < 0 )
	{
		std::cerr << "Failed to decrypt challenege" << std::endl;
		return false;
	}
	delete [] enc_chal;


	/*
 	 * HASH PRNG CHALLENGE AND SEND BACK COMPLETING HANDSHAKE.
 	 */

	// 160 bits * 1bit/ 8 bytes
	unsigned char hash[20];
	SHA1( dec_chal, 64, hash );

	unsigned char *enc_hash = new unsigned char[ 128 ];
	if( RSA_private_encrypt( 20, hash, enc_hash, rsa_priv, RSA_PKCS1_PADDING ) < 0 )
	{
		std::cerr << "Failed to encrypt hash" << std::endl;
		return false;
	}

	SSL_write( sp, enc_hash, 128 ); 

	delete [] enc_hash;
	return true;
}

bool ssl_server::handle_op( SSL *sp )
{
	// Read first byte to decide whether a store or retriece request.
	char *op = new char(1);
	SSL_read( sp, (unsigned char*)op, 1 );

	if( strncmp( "s", op, 1 ) == 0 )
	{
		std::cout << "STORE REQUESTED FROM CLIENT" << std::endl;

		unsigned char *enc_file = new unsigned char[ 128 ];
		// Read in file contents (size of rsa key)
		SSL_read( sp, enc_file, 128 );

		unsigned char *file_name = new unsigned char[128];
		//Read in file name
		SSL_read( sp, file_name, 128 );

		std::cout << "STORING ENC FILE WITH NAME: " << file_name << std::endl;
		std::ofstream of( (char*)file_name );
		of.write( (char*)enc_file, 128 );

		of.close();
		delete [] enc_file;
		delete [] file_name;
	}

	else if( strncmp( "r", op, 1 ) == 0 )
	{
		std::cout << "RETRIEVE REQUESTED FROM CLIENT" << std::endl;
		unsigned char *file = new unsigned char[128];
		SSL_read( sp, file, 128 );

		FILE *fp = fopen( (char*)file, "rb" );
		char *fc = 0;
		if( fp )
		{
			fseek( fp, 0, SEEK_END );
			long position = ftell(fp);
			fseek( fp, 0, SEEK_SET );
			
			fc = new char[position];
			fread( fc, position, 1, fp );
			fclose( fp );
		}
		else
			std::cerr << "File not found" << std::endl;

		// Send enc file to client;
		if( fc )
		{
			std::cout << "SENDING FILE: \n" << file << std::endl <<  std::endl;
			SSL_write( sp, fc, 128 );
			delete [] fc;
		}

		delete [] file;
	}
	else
		std::cout << "NOTHING TO DO" << std::endl;

	delete op;
	std::cout << "DONE" << std::endl;	
	return true;
}

bool ssl_server::run()
{
	BIO *sock_bio;
	// Holds the data for the TLS/SSL connection.
	SSL *ssl_ptr;
	int client_sock;
	pid_t pid;
	

	for(;;)
	{
		if( ( client_sock = accept( sock, NULL, NULL ) ) < 0 )
		{
			std::cerr << "Failed to accept a new connection on a socket" << std::endl;
			return false;
		}

		if( ( pid = fork() ) < 0 )
		{
			std::cerr << "Failed to create a child process" << std::endl;
			return false;
		}

		// The child process
		else if( pid == 0 )
		{
			std::cout << "\n--------------" << std::endl;
			std::cout << "NEW CONNECTION" << std::endl;
			sock_bio = BIO_new_socket( client_sock, BIO_NOCLOSE );
			// Create new connection object using the context
			ssl_ptr = SSL_new( context_ptr );
			SSL_set_bio( ssl_ptr, sock_bio, sock_bio );

			if( SSL_accept( ssl_ptr ) <= 0 )
				std::cerr << "Failed to initiate client/host handshake." << std::endl;

			if( !handshake( ssl_ptr ) )
			{
				std::cerr << "Failed to authenticate client" << std::endl;
				SSL_free( ssl_ptr );
				exit(1);
			}


			// Handle clients desired operation
			if( !handle_op( ssl_ptr ) )
			{
				std::cerr << "Failed to realize clients request" << std::endl;
				SSL_free( ssl_ptr );
				exit(1);
			}


			SSL_free( ssl_ptr );
			exit(0); // Exit the child
		}

		if( close( client_sock ) < 0 )
				std::cout << "Parent failed to close()\n";
	}
	return true;
}
