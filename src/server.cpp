//
// Simple chat server for TSAM-409
//
// Command line: ./chat_server 4000
//
// Author: Jacky Mallett (jacky@ru.is)
//
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <string.h>
#include <algorithm>
#include <map>
#include <vector>
#include <list>

#include <sys/un.h>
#include <iomanip>

#include <fcntl.h>

#include <iostream>
#include <sstream>
#include <thread>
#include <map>

#include <unistd.h>

// fix SOCK_NONBLOCK for OSX
#ifndef SOCK_NONBLOCK
#include <fcntl.h>
#define SOCK_NONBLOCK O_NONBLOCK
#endif

#define BACKLOG 5 // Allowed length of queue of waiting connections

// Simple class for handling connections from all_clients_servers.
//
// Client_Server(int socket) - socket to send/receive traffic from client.
class Client_Server
{
public:
    int sock;         // socket of client connection
    std::string name; // Limit length of name of client's user
    int port;         // port of client
    std::string ip;   // ip address of client
    bool server;      // true if connection is from another server

    Client_Server(int socket, bool is_server)
    {
        sock = socket;
        server = is_server;
    }

    ~Client_Server() {} // Virtual destructor defined for base class
};

// Note: map is not necessarily the most efficient method to use here,
// especially for a server with large numbers of simulataneous connections,
// where performance is also expected to be an issue.
//
// Quite often a simple array can be used as a lookup table,
// (indexed on socket no.) sacrificing memory for speed.

std::map<int, Client_Server *> all_clients_servers; // Lookup table for per Client_Server information

// map to store all stored messagges, the key is the group that that should receive the message
std::map<std::string, std::vector<std::string>> stored_messages;

// Open socket for specified port.
//
// Returns -1 if unable to create the socket for any reason.

int open_socket(int portno)
{
    struct sockaddr_in sk_addr; // address settings for bind()
    int sock;                   // socket opened for this port
    int set = 1;                // for setsockopt

    // Create socket for connection. Set to be non-blocking, so recv will
    // return immediately if there isn't anything waiting to be read.
#ifdef __APPLE__
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        perror("Failed to open socket");
        return (-1);
    }
#else
    if ((sock = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0)) < 0)
    {
        perror("Failed to open socket");
        return (-1);
    }
#endif

    // Turn on SO_REUSEADDR to allow socket to be quickly reused after
    // program exit.

    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &set, sizeof(set)) < 0)
    {
        perror("Failed to set SO_REUSEADDR:");
    }
    set = 1;
#ifdef __APPLE__
    if (setsockopt(sock, SOL_SOCKET, SOCK_NONBLOCK, &set, sizeof(set)) < 0)
    {
        perror("Failed to set SOCK_NOBBLOCK");
    }
#endif
    memset(&sk_addr, 0, sizeof(sk_addr));

    sk_addr.sin_family = AF_INET;
    sk_addr.sin_addr.s_addr = INADDR_ANY;
    sk_addr.sin_port = htons(portno);

    // Bind to socket to listen for connections from all_clients_servers

    if (bind(sock, (struct sockaddr *)&sk_addr, sizeof(sk_addr)) < 0)
    {
        perror("Failed to bind to socket:");
        return (-1);
    }
    else
    {
        return (sock);
    }
}

// Close a client's connection, remove it from the client list, and
// tidy up select sockets afterwards.

void closeClient(int clientSocket, fd_set *openSockets, int *maxfds)
{
    // Remove client from the all_clients_servers list
    all_clients_servers.erase(clientSocket);

    // If this client's socket is maxfds then the next lowest
    // one has to be determined. Socket fd's can be reused by the Kernel,
    // so there aren't any nice ways to do this.

    if (*maxfds == clientSocket)
    {

        *maxfds = 0;

        for (auto const &p : all_clients_servers)
        {
            *maxfds = std::max(*maxfds, p.second->sock);
        }
    }

    // And remove from the list of open sockets.

    FD_CLR(clientSocket, openSockets);
}

// Process command from client on the server

void clientCommand(int clientSocket, fd_set *openSockets, int *maxfds, char *buffer)
{
    std::vector<std::string> tokens;
    std::string token;

    // Split command from client into tokens for parsing
    std::stringstream stream(buffer);

    while (stream >> token)
    {
        tokens.push_back(token);
    }

    if ((tokens[0].compare("CONNECT") == 0) && (tokens.size() == 2))
    {
        all_clients_servers[clientSocket]->name = tokens[1];
    }
    else if (tokens[0].compare("LEAVE") == 0)
    {
        // Close the socket, and leave the socket handling
        // code to deal with tidying up all_clients_servers etc. when
        // select() detects the OS has torn down the connection.
        std::cout << "here before" << std::endl;
        closeClient(clientSocket, openSockets, maxfds);
        std::cout << "here after" << std::endl;
    }
    else if (tokens[0].compare("WHO") == 0)
    {
        std::cout << "Who is logged on" << std::endl;
        std::string msg;

        for (auto const &names : all_clients_servers)
        {
            msg += names.second->name + ",";
        }
        // Reducing the msg length by 1 loses the excess "," - which
        // granted is totally cheating.
        send(clientSocket, msg.c_str(), msg.length() - 1, 0);
    }

    // This is slightly fragile, since it's relying on the order
    // of evaluation of the if statement.
    else if ((tokens[0].compare("MSG") == 0) && (tokens[1].compare("ALL") == 0))
    {
        std::string msg;
        for (auto i = tokens.begin() + 2; i != tokens.end(); i++)
        {
            msg += *i + " ";
        }

        for (auto const &pair : all_clients_servers)
        {
            send(pair.second->sock, msg.c_str(), msg.length(), 0);
        }
    }
    else if (tokens[0].compare("MSG") == 0)
    {
        for (auto const &pair : all_clients_servers)
        {
            if (pair.second->name.compare(tokens[1]) == 0)
            {
                std::string msg;
                for (auto i = tokens.begin() + 2; i != tokens.end(); i++)
                {
                    msg += *i + " ";
                }
                send(pair.second->sock, msg.c_str(), msg.length(), 0);
            }
        }
    }
    else
    {
        std::cout << "Unknown command from client:" << tokens[0] << std::endl;
    }
}

std::string send_message(int socket, std::string req)
{
    req = "*" + req + "#";
    return "";
}

// void append_message(std::string group, std::string msg)
// {
//     if (stored_messages.find(group) != stored_messages.end())
//     {
//         // if there is already a vector in the map
//         stored_messages[group].push_back(msg);
//     }
//     // create the vector and add the first message
//     else
//     {
//         stored_messages[group] = std::vector<std::string>();
//         stored_messages[group].push_back(msg);
//     }
// }

void serverCommand(int clientSocket, fd_set *openSockets, int *maxfds, std::vector<std::string> tokens)
{

    if ((tokens[1].compare("QUERYSERVERS") == 0) && (tokens.size() == 3))
    {
        std::cout << tokens[1] << tokens[2] << std::endl;
    }
    else if (tokens[1].compare("CONNECTED") == 0)
    {
        std::cout << tokens[1] << tokens[2] << tokens[3] << tokens[4] << std::endl;
    }
    else if (tokens[1].compare("KEEPALIVE") == 0)
    {
        std::cout << tokens[0] << tokens[1] << std::endl;
        int message_count = atoi(tokens[1].c_str());
        if (message_count > 0)
        {
            std::string request = "GET_MSG,P3_GROUP_1";
            std::string response = send_message(clientSocket, request);
            std::cout << response << std::endl;
        }
    }
    else if (tokens[1].compare("GET_MSG") == 0)
    {
        // get group number
        std::string group = tokens[1];
        // std::cout << tokens[1] << tokens[2] << std::endl;
        if (stored_messages.find(group) != stored_messages.end())
        {
            std::vector requested_messages = stored_messages[group];
            for (std::string request : requested_messages)
            {
                std::string response = send_message(clientSocket, request);
                std::cout << response << std::endl;
            }
        }
    }
    else if (tokens[1].compare("SEND_MSG") == 0)
    {
        std::cout << tokens[1] << tokens[2] << tokens[3] << std::endl;
        std::string to_group = tokens[1];
        std::string from_group = tokens[2];
        std::string msg = tokens[0] + tokens[1] + tokens[2] + tokens[3];
        stored_messages[to_group].push_back(msg);
        int count = stored_messages[to_group].size();
        for (auto const &pair : all_clients_servers)
        {
            Client_Server *client = pair.second;
            if (client->name.compare(to_group) == 0)
            {
                std::string msg = "KEEPALIVE," + count;
                std::string response = send_message(clientSocket, msg);
                std::cout << response << std::endl;
                break;
            }
        }
    }
    else if (tokens[1].compare("LEAVE") == 0)
    {
        std::cout << tokens[1] << tokens[2] << tokens[3] << std::endl;
    }
    else if (tokens[1].compare("STATUSREQ") == 0)
    {
        std::cout << tokens[1] << tokens[2] << std::endl;
    }
    else if (tokens[1].compare("STATUSRESP") == 0)
    {
        std::cout << tokens[1] << tokens[2] << tokens[3] << std::endl;
    }
    else
    {
        std::cout << "Unknown command from server:" << tokens[0] << std::endl;
    }
}

std::vector<std::string> get_message(char *buffer)
{
    std::vector<std::string> tokens;
    std::string token;

    // Split command from client into tokens for parsing
    std::stringstream stream(buffer);

    while (std::getline(stream, token, ','))
    {
        tokens.push_back(token);
    }

    return tokens;
}

int main(int argc, char *argv[])
{
    bool finished;
    int clientListenSock; // Socket for client connections to server
    int clientSock;       // Socket of connecting client
    int serverListenSock; // Socket for server connections to server
    int serverSock;       // Socket of connecting server
    fd_set openSockets;   // Current open sockets
    fd_set readSockets;   // Socket list for select()
    fd_set exceptSockets; // Exception socket list
    int maxfds;           // Passed to select() as max fd in set
    struct sockaddr_in client;
    socklen_t clientLen;
    char buffer[1025]; // buffer for reading from all_clients_servers

    if (argc != 2)
    {
        printf("Usage: chat_server <ip port>\n");
        exit(0);
    }

    // Setup client socket for server to listen to

    clientListenSock = open_socket(5050);
    printf("Listening for client connections on port: %d\n", 5050);

    if (listen(clientListenSock, BACKLOG) < 0)
    {
        printf("Client_Server listening failed on port %d\n", 5050);
        exit(0);
    }
    else
    // Add listen socket to socket set we are monitoring
    {
        FD_ZERO(&openSockets);
        FD_SET(clientListenSock, &openSockets);
        maxfds = clientListenSock;
    }

    // Setup server socket for server to listen to

    serverListenSock = open_socket(atoi(argv[1]));
    printf("Listening for server connections on port: %d\n", atoi(argv[1]));

    if (listen(serverListenSock, BACKLOG) < 0)
    {
        printf("Server listening failed on port %d\n", atoi(argv[1]));
        exit(0);
    }
    else
    // Add listen socket to socket set we are monitoring
    {
        FD_SET(serverListenSock, &openSockets);
        maxfds = std::max(maxfds, serverListenSock);
    }

    finished = false;

    while (!finished)
    {

        // Get modifiable copy of readSockets
        readSockets = exceptSockets = openSockets;
        memset(buffer, 0, sizeof(buffer));

        // Look at sockets and see which ones have something to be read()
        int n = select(maxfds + 1, &readSockets, NULL, &exceptSockets, NULL);

        if (n < 0)
        {
            perror("select failed - closing down\n");
            finished = true;
        }
        else
        {
            // First, accept  any new client connections to the server on the client listening socket
            if (FD_ISSET(clientListenSock, &readSockets))
            {
                clientSock = accept(clientListenSock, (struct sockaddr *)&client,
                                    &clientLen);
                printf("Client_Server - accept***\n");
                // Add new client to the list of open sockets
                FD_SET(clientSock, &openSockets);

                // And update the maximum file descriptor
                maxfds = std::max(maxfds, clientSock);

                // create a new client to store information.
                all_clients_servers[clientSock] = new Client_Server(clientSock, false);

                // Decrement the number of sockets waiting to be dealt with
                n--;

                printf("Client_Server connected on server: %d\n", clientSock);
            }
            // Next, accept  any new server connections to the server on the server listening socket
            if (FD_ISSET(serverListenSock, &readSockets))
            {
                serverSock = accept(serverListenSock, (struct sockaddr *)&client,
                                    &clientLen);
                printf("Server - accept***\n");
                // Add new client to the list of open sockets
                FD_SET(serverSock, &openSockets);

                // And update the maximum file descriptor
                maxfds = std::max(maxfds, serverSock);

                char ip_str[INET_ADDRSTRLEN];
                // now get it back and print it
                inet_ntop(AF_INET, &(client.sin_addr), ip_str, INET_ADDRSTRLEN);

                // create a new client to store information.
                Client_Server *new_server = new Client_Server(serverSock, true);
                new_server->ip = ip_str;
                new_server->port = client.sin_port;
                all_clients_servers[serverSock] = new_server;

                // Decrement the number of sockets waiting to be dealt with
                n--;

                printf("Server connected on server: %d\n", serverSock);
            }
            // Now check for commands from all_clients_servers
            while (n-- > 0)
            {

                for (auto const &pair : all_clients_servers)
                {
                    Client_Server *client = pair.second;

                    if (FD_ISSET(client->sock, &readSockets))
                    {
                        // recv() == 0 means client has closed connection
                        if (recv(client->sock, buffer, sizeof(buffer), MSG_DONTWAIT) == 0)
                        {
                            printf("Client_Server closed connection: %d", client->sock);
                            close(client->sock);
                            // TODO: close servers
                            closeClient(client->sock, &openSockets, &maxfds);
                        }
                        // We don't check for -1 (nothing received) because select()
                        // only triggers if there is something on the socket for us.
                        else
                        {

                            std::vector<std::string> tokens = get_message(buffer);

                            if (tokens[0].compare("*") == 0)
                            {
                                serverCommand(client->sock, &openSockets, &maxfds, tokens);
                            }
                            else
                            {
                                clientCommand(client->sock, &openSockets, &maxfds, buffer);
                            }
                        }
                        break;
                    }
                }
            }
        }
    }
}
