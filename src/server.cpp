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

#include <sys/un.h>
#include <iomanip>
#include <fcntl.h>



#include <net/if.h>
#include <ifaddrs.h>
#include <errno.h>


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



std::string getIP()
{
    struct ifaddrs *myaddrs, *ifa;
    void *in_addr;
    char buf[64];

    if(getifaddrs(&myaddrs) != 0)
    {
        perror("getifaddrs");
        exit(1);
    }

    for (ifa = myaddrs; ifa != NULL; ifa = ifa->ifa_next)
    {
        if (ifa->ifa_addr == NULL)
            continue;
        if (!(ifa->ifa_flags & IFF_UP))
            continue;

        switch (ifa->ifa_addr->sa_family)
        {
            case AF_INET:
            {
                struct sockaddr_in *s4 = (struct sockaddr_in *)ifa->ifa_addr;
                in_addr = &s4->sin_addr;
                break;
            }

            case AF_INET6:
            {
                struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)ifa->ifa_addr;
                in_addr = &s6->sin6_addr;
                break;
            }

            default:
                continue;
        }
        std::string name = ifa->ifa_name;
        if (!inet_ntop(ifa->ifa_addr->sa_family, in_addr, buf, sizeof(buf)))
        {
            printf("%s: inet_ntop failed!\n", ifa->ifa_name);
        }
        else if (name.compare("eno16780032")==0)
        {

            std::string str (buf);
            return str;
        }
        else if (name.compare("enp0s3")==0)
        {

            std::string str (buf);
            return str;
        }
        
    }

    freeifaddrs(myaddrs);
    return (std::string) "0";
}


// Simple class for handling connections from clients.
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


std::string server_addr = getIP();
std::string port_addr;
std::map<int, Client_Server *> all_clients_servers; // Lookup table for per Client_Server information
std::map<int, std::map<std::string, Client_Server *>> servers_connections;
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
        
        closeClient(clientSocket, openSockets, maxfds);
        
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

void serverCommand(int serverSocket, fd_set *openSockets, int *maxfds, std::vector<std::string> tokens)
{
    std::cout<<tokens[0]<<std::endl;

    if ((tokens[0].compare("QUERYSERVERS") == 0))
    {


        //todo: add the groupid and ipaddr. and portnr.

        all_clients_servers[serverSocket]->name = tokens[1];

        

        std::string msg = "*CONNECTED,P3_group_1,"+server_addr+ ',' +port_addr;
    
        for (auto const &pair : all_clients_servers)
        {
            if(pair.second->server){
                if (pair.second->name.compare(tokens[1]) != 0)
                {
                    msg+= ";"+pair.second->name+","+pair.second->ip+",";
                    msg+=std::to_string(pair.second->port);
                }
            }
        }
        msg+="#";
        send(serverSocket, msg.c_str(), msg.length(), 0);
        
        std::string req= "*QUERYSERVERS,P3_group_1#";
        send(serverSocket, req.c_str(), req.length(), 0);
    }
    else if (tokens[0].compare("CONNECTED") == 0)
    {
        if (all_clients_servers[serverSocket]->name.compare(tokens[1]) == 0){
            std::map<std::string, Client_Server *> server_servers;
            bool skip = false;
            for (int i =1;i <= ((tokens.size()-4)/3);i++){

                for (auto const &pair : all_clients_servers){
                    std::cout<<i<<std::endl;
                    if (pair.second->name.compare(tokens[(3*i)+1]) == 0)
                    {
                        skip = true;
                        break;
                    }
                }

                if (skip){
                    skip = false;
                }
                else{
                    std::cout<<"made it "<<i<<std::endl;
                    Client_Server *new_server = new Client_Server(serverSocket, true);
                    std::string name=tokens[(i*3)+1];
                    std::cout<<name<<(i*3)+1<<std::endl;
                    std::cout<<tokens.size()<<std::endl;
                    new_server->name = name;
                    new_server->ip = tokens[(3*i)+2];
                    new_server->port = atoi(tokens[(3*i)+3].c_str());
                    server_servers[name] = new_server;
                    std::cout<<"server name: ";
                    std::cout<<new_server->name<<std::endl;
                }
            }
            servers_connections[serverSocket] =server_servers;
            
            
        }
        else{
            std::cout<<all_clients_servers[serverSocket]->name<<std::endl;
            std::cout<<tokens[1]<<std::endl;
            std::cout<<"not recognized server"<<std::endl;
        }
    }
    else if (tokens[0].compare("KEEPALIVE") == 0)
    {
        std::cout << tokens[1] << tokens[2] << std::endl;
    }
    else if (tokens[0].compare("GET_MSG") == 0)
    {
        std::cout << tokens[0] << tokens[1] << std::endl;
    }
    else if (tokens[0].compare("SEND_MSG") == 0)
    {
        std::cout << tokens[0] << tokens[1] << tokens[2] << std::endl;
    }
    else if (tokens[0].compare("LEAVE") == 0)
    {
        std::cout << tokens[0] << tokens[1] << tokens[2] << std::endl;
    }
    else if (tokens[0].compare("STATUSREQ") == 0)
    {
        std::cout << tokens[0] << tokens[1] << std::endl;
    }
    else if (tokens[0].compare("STATUSRESP") == 0)
    {
        std::cout << tokens[0] << tokens[1] << tokens[2] << std::endl;
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
    std::string mini;

    // Split command from client into tokens for parsing
    std::stringstream stream(buffer);
    
    while (std::getline(stream, token, ','))
    {
        std::stringstream ss(token);
        while(std::getline(ss, mini, ';')){
            mini.erase(std::remove_if(mini.begin(),mini.end(),::isspace),mini.end());
            tokens.push_back(mini);
        }
        
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
    char buffer[1025]; // buffer for reading from clients
    port_addr = argv[1];
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
                            std::string fw = tokens[0];
                            tokens[0]=fw.substr(1);
                            
                            char fl = fw[0];
                            if ( fl == '*' )
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
