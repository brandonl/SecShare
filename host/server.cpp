#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <iostream>
#include "ssl_server.h"
#include <getopt.h>
#include <cstring>

int main( int argc, char **argv )
{
	if( argc < 2 )
	{
		std::cerr << "Usage: " << argv[0] << " [-port <port number>]" << std::endl;
		return 1;
	}

	int opt = 0, opt_index = 0;
	unsigned short port = 0;
	const struct option long_opts[] = { { "port", required_argument, 0, 'p' } };

	for( ;; )
	{
		if( ( opt = getopt_long_only( argc, argv, "p", long_opts, &opt_index ) ) == -1 )
			break;
		switch( opt )
		{
			case 'p':
				port = atoi( optarg );
			break;

			default:
				std::cerr << "Unkown option encountered" << std::endl;
			break;
		}
	}

	ssl_server serv( port, 5 );
	serv.init();
	serv.run();

	return 0;
}
