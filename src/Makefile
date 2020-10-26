all: server client

server: server.cpp
	g++ -Wall -std=c++11 -pthread server.cpp -o server

client: client.cpp
	g++ -Wall -std=c++11 -pthread client.cpp -o client



clean:
	rm server
	rm client
