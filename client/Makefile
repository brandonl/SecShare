CXX=g++
CXXFLAGS=-g -W -Wall -pedantic -ansi
LFLAGS=-lcrypto -lssl -lpthread

server: ssl_server.o server.cpp
		$(CXX) $(CXXFLAGS) -o server server.cpp ssl_server.o $(LFLAGS)

client: ssl_client.o client.cpp
		$(CXX) $(CXXFLAGS) -o client client.cpp ssl_client.o $(LFLAGS)

ssl_server: ssl_server.h ssl_server.cpp
		$(CXX) $(CXXFLAGS) -o ssl_server.o -c ssl_server.cpp $(LFLAGS)
	
ssl_client: ssl_client.h ssl_client.cpp
		$(CXX) $(CXXFLAGS) -s ssl_client.o -c ssl_server.cpp $(LFLAGS)

clean:
		rm -rf *~ server client *.o
