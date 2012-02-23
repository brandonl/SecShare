#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <iostream>
#include "ssl_client.h"
#include <getopt.h>
#include <cstring>

struct client_opts
{
	client_opts()
		: filename(0), server_ip(0), option(0)
	{}

	char *filename;
	unsigned short port;
	char *server_ip;
	char *option;
};

inline void out_error( const char *exe )
{
	std::cerr 	<< "Usage: " << exe
				<<" [ -server <server_address> -port" 
				<< " <server_port> -file <filename> -operation"
				<< " <store or retrieve> ]" << std::endl;
}

int main( int argc, char **argv )
{
	if( argc < 8 )
	{
		out_error( argv[0] );
		return 1;
	}

	// Construct to hold clients options
	client_opts config;

	// Proccess command line arguments using get_opt_long from GNU foundation.
	int opt = 0, opt_index = 0;
	const struct option long_opts[] =
	{
		{ "server", 	required_argument, 0, 's' },
		{ "port", 		required_argument, 0, 'p' },
		{ "operation", 	required_argument, 0, 'o' },
		{ "file", 		required_argument, 0, 'f' }
	};

	for(;;)
	{
		if( ( opt = getopt_long_only( argc, argv, "s:p:o", long_opts, &opt_index ) ) == -1 )
			break; //End of options

		switch( opt )
		{
			case 's':
				config.server_ip = optarg;
			break;

			case 'p':
				config.port = atoi( optarg );
			break;

			case 'o':
				config.option = optarg;
			break;
		
			case 'f':
				config.filename = optarg;
			break;

			default:
				std::cerr << "Unknown option encountered" << std::endl;
			break;
		}
	}


	// Check user input for correctness
	char s[] = "store", r[] = "retrieve";
	{
		if( (strcmp( s, config.option) != 0 ) && (strcmp( r, config.option ) != 0) )
			out_error( argv[0] );
		if( !config.filename || !config.server_ip || !config.option )
			out_error( argv[0] );
	}

	{
		ssl_client client;
		if( !client.init() )
			exit(1);

		if( !client.conn( config.server_ip, config.port ) )
			exit(1);

		// Decide whether to store or retrieve given filename
		// based on given operation	
		if( strcmp( s, config.option ) == 0 )
			client.store( config.filename );
		else
			client.retrieve( config.filename );
	}

	return 0;
}
