#include "ssl_client.h"
#include <openssl/err.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <iostream>
#include <openssl/rand.h>
#include <cstring>
#include <cstdio>

ssl_client::ssl_client()
	:	ssl_ptr(0),
		context_ptr(0),
		rsa_pub(0),
		rsa_priv(0),
		server_pub(0),
		friend_pub(0)
{
}


ssl_client::~ssl_client()
{
	destroy();
}

void ssl_client::destroy()
{
	if( ssl_ptr )	
		SSL_shutdown( ssl_ptr );
	if( ssl_ptr ) 
		SSL_free( ssl_ptr );
	if( rsa_pub )
		RSA_free( rsa_pub );
	if( rsa_priv )
		RSA_free( rsa_priv );
	if( server_pub )
		RSA_free( server_pub );
	if( friend_pub )
		RSA_free( friend_pub );
	close( sock );
	ERR_free_strings();
	EVP_cleanup();
	if( context_ptr ) 
		SSL_CTX_free( context_ptr );
}

bool ssl_client::init_rsa()
{
	rsa_pub = PEM_read_RSA_PUBKEY( fopen( "keys/rsa.pub", "r" ), 0, 0, 0 );
	if( !rsa_pub )
	{
		std::cout << "Public key failed" << std::endl;
		return false;
	}

	rsa_priv = PEM_read_RSAPrivateKey( fopen( "keys/rsa.priv", "r" ), 0, 0, 0 );
	if( !rsa_priv )
	{
		std::cout << "Private key failed" << std::endl;
		return false;
	}

	friend_pub = PEM_read_RSA_PUBKEY( fopen( "keys/friend.pub", "r" ), 0, 0, 0 );
	if( !friend_pub )
	{
		std::cout << "Friend Public key failed" << std::endl;
		return false;
	}

	server_pub = PEM_read_RSA_PUBKEY( fopen( "keys/server.pub", "r" ), 0, 0, 0 );
	if( !server_pub )
	{
		std::cout << "Server Public key failed" << std::endl;
		return false;
	}

	return true;
}

bool ssl_client::init()
{
	SSL_library_init();
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();

	context_ptr = SSL_CTX_new( SSLv23_client_method() );

	if( !context_ptr )
	{
		ERR_print_errors_fp( stderr );
		return false;
	}

	SSL_CTX_set_verify( context_ptr, SSL_VERIFY_NONE, 0 );
	SSL_CTX_set_cipher_list( context_ptr, "ADH-AES256-SHA" );

	if( !init_rsa() )
		std::cerr << "failed to init rsa keys" << std::endl;

	return true;
}

bool ssl_client::handshake()
{
	/*
 	 * ENC PRNG CHALLENEGE AND SEND TO SERVER
 	 */

	// Challenege mus be at most size of rsa.
	unsigned char challenge[64] = {0};

	// Step 2 Seed PRNG and generate rand challenge
	std::cout << "CLIENT STEP 2" << std::endl;
	RAND_add( "zbsdkfhjeiryujddkdjfoqwihsyfcnswkzldoxhhdelkjsdglkjsdjghjsghex", 64, 6.0 );
	RAND_bytes( challenge, sizeof(challenge) );
	
	unsigned char *enc_chal = new unsigned char[ 128 ];

	// Step 3 Encrypt the chellenge with server's public key and send
	std::cout << "CLIENT STEP 3" << std::endl;
	if( RSA_public_encrypt( 64, challenge, enc_chal, server_pub, RSA_PKCS1_PADDING ) < 0 )
	{
		std::cerr << "Failed to encrypt" << std::endl;
		return false;
	}

	SSL_write( ssl_ptr, enc_chal, 128 );

	/*
 	 * RECV HASHED CHALLENGE...UNENC AND COMPARE
 	 */
	// Step 4 Hash the challenege.
	std::cout << "CLIENT STEP 4" << std::endl;
	unsigned char hash[20] = {0};
	SHA1( challenge, 64, hash );

	unsigned char recv_enc_hash[128] = {0};
	SSL_read( ssl_ptr, recv_enc_hash, 128 );

	// Step 5 Recover the hash from the server through decryption	
	std::cout << "CLIENT STEP 5" << std::endl;
	unsigned char dec_hash[20] = {0};
	if( RSA_public_decrypt( 128, recv_enc_hash, dec_hash, server_pub, RSA_PKCS1_PADDING ) < 0 )
	{
		std::cerr << "Failed to decrypt" << std::endl;
		return false;
	}
 

	// Step 6 Compare the local hash with the decrypted hash from server to verify
	std::cout << "CLIENT STEP 6" << std::endl;
	if( strncmp( (char*)hash, (char*)dec_hash, 20 ) != 0 )
	{
		std::cerr << "Failed to authenticate hashed challenge recv from server." << std::endl;
		return false;
	}
	else
		std::cout << "Authentication Complete!" << std::endl;
	std::cout << std::endl;

	return true;
}

bool ssl_client::conn( const char* server_ip, unsigned short port )
{
	struct sockaddr_in server_addr;

	if( ( sock = socket( AF_INET, SOCK_STREAM, IPPROTO_TCP ) ) < 0 )
	{
		std::cerr << "Failed to create socket" << std::endl;
		return false;
	}

	memset( &server_addr, 0, sizeof( server_addr ) );
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons( port );
	server_addr.sin_addr.s_addr = inet_addr( server_ip );

	if( connect( sock, reinterpret_cast<struct sockaddr* >(&server_addr), sizeof(server_addr) ) < 0 )
	{
		std::cerr << "Failed to connect to server" << std::endl;
		return false;
	}

	ssl_ptr = SSL_new( context_ptr );
	if( !ssl_ptr )
	{
		std::cerr << "Failed to create new SSL structure" << std::endl;
		return false;
	}

	BIO *sock_bio = BIO_new_socket( sock, BIO_NOCLOSE );
	SSL_set_bio( ssl_ptr, sock_bio, sock_bio );


	if(  SSL_connect( ssl_ptr ) <= 0 )
	{
		std::cerr << "Failed to connect via SSL" << std::endl;
		return false;
	}

	if( !handshake() )
	{
		std::cerr << "Failed to complete authentication" << std::endl;
		return false;
	}


	return true;
}

void ssl_client::store( const char *fn )
{
	// Make sure file exists locally before contacting server...
	char *fc = 0;
	FILE *f = fopen( fn, "rb" );
	if( f ) 
	{
		fseek( f, 0, SEEK_END );
		long position = ftell(f);
		fseek( f, 0, SEEK_SET );

		fc = new char[position];
		fread( fc, position, 1, f );
		fclose( f );
	}
	else
	{
		std::cerr << "File not found" << std::endl;
		return;
	}

	// Tell the server this request is a store request...
	char s[] = "s";
	SSL_write( ssl_ptr, (unsigned char*)s, 1 );	

	// Client wishes to store the file
	std::cout << "CLIENT STORING FILE INTENDED FOR FRIEND" << std::endl;

	/* SINCE THE RSA KEY IS 128 BYTES THE FILE MUST BE <= 128 BYTES SINCE
       WE ENCRYPT THE WHOLE THING */
	//Encrpt the file with friend public key
	std::cout << "ENCRYPTING FILE WITH FRIENDs PUBLIC KEY" << std::endl;
	unsigned char *enc_file = new unsigned char[ 128 ];
 	RSA_public_encrypt( strlen(fc), (unsigned char*)fc, enc_file, friend_pub, RSA_PKCS1_PADDING );

	// Send enc file and filename to server and close connection.
	std::cout << "SENDING ENCRYPTED FILE AND FILE NAME" << std::endl;
	SSL_write( ssl_ptr, enc_file, 128 );
	SSL_write( ssl_ptr, (unsigned char*)fn, 128 );

	std::cout << "CLOSING CONNECTION" << std::endl;

	if( fc )
		delete [] fc;
	delete [] enc_file;
}

void ssl_client::retrieve( const char *fn )
{
	// Tell the server this request is a retrieve request.
	char r[] = "r";
	SSL_write( ssl_ptr, (unsigned char*)r, 1 );

	// Client wishes to retrieve file with name fn
	std::cout << "CLIENT RETRIEVING FILE NAME: " << fn << " FROM FRIEND THROUGH SERVER" << std::endl;
	// Send file request
	SSL_write( ssl_ptr, fn, 128 );

	unsigned char *file = new unsigned char[128];
	SSL_read( ssl_ptr, file, 128 );

	// Decrypt and display
	std::cout << "DECRYPTING FILE...FILE CONTENTS: " << std::endl;
	unsigned char *dec_file = new unsigned char[128];
	memset( dec_file, 0, 128 );

	if( RSA_private_decrypt( 128, file, dec_file, rsa_priv, RSA_PKCS1_PADDING ) < 0 )
		std::cerr << "Decryption failed" << std::endl;
	std::cout << dec_file << std::endl;

	std::cout << "CLOSING CONNECTION" << std::endl;
	if( file )
		delete [] file;
	if( dec_file )
		delete [] dec_file;
}
