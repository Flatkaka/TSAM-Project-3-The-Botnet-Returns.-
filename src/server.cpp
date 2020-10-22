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
#include <net/if.h>
#include <algorithm>
#include <map>
#include <vector>
#include <list>
#include <fstream>
#include <time.h>

#include <set>
#include <thread>
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

std::string getCurrentDateTime()
{
    time_t now = time(0);
    struct tm tstruct;
    char buf[80];
    tstruct = *localtime(&now);

    strftime(buf, sizeof(buf), "%Y-%m-%d %X", &tstruct);
    return std::string(buf);
};

void log_to_file(std::string logMsg)
{

    std::string filePath = "./messages.txt";
    std::string now = getCurrentDateTime();
    std::ofstream ofs(filePath.c_str(), std::ios_base::out | std::ios_base::app);
    ofs << now << '\t' << logMsg << '\n';
    ofs.close();
}

std::string getIP()
{
    struct ifaddrs *myaddrs, *ifa;
    void *in_addr;
    char buf[64];

    if (getifaddrs(&myaddrs) != 0)
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
        else if (name.compare("eno16780032") == 0)
        {

            std::string str(buf);
            return str;
        }
        else if (name.compare("enp0s3") == 0)
        {

            std::string str(buf);
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
    bool verified;
    bool sent;

    Client_Server(int socket, bool is_server)
    {
        sock = socket;
        server = is_server;
        verified = false;
        sent = false;
    }

    ~Client_Server() {} // Virtual destructor defined for base class
};

// Note: map is not necessarily the most efficient method to use here,
// especially for a server with large numbers of simulataneous connections,
// where performance is also expected to be an issue.
//
// Quite often a simple array can be used as a lookup table,
// (indexed on socket no.) sacrificing memory for speed.

// map to store all stored messagges, the key is the group that that should receive the message

//global variables.
std::map<std::string, std::vector<std::string>> stored_messages;
std::map<int, Client_Server *> all_clients_servers;                        // Lookup table for per Client_Server information
std::map<int, std::map<std::string, Client_Server *>> servers_connections; //lookuptable to see what server are connected to the servers our server is connect.
// std::string server_addr = "0.0.0.0";
std::string server_addr = getIP();
std::string port_addr;
std::string group_name = "P3_GROUP_1"; // global variable storing the name of our group
int server_count;                      // number of servers connected
std::list<int> disconnectedClients;

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

std::string send_message(int socket, std::string req)
{
    int nwrite = send(socket, req.c_str(), req.length(), 0);
    std::cout << "\033[1;33mWe send to " << all_clients_servers[socket]->name << " number:" << socket << ": \033[0m" << std::endl;
    std::cout << req << std::endl;
    if (nwrite < 0)
    {
        perror("send() to server failed: ");
    }
    return "success";
}

std::string replace(std::string input, std::string from, std::string to)
{
    size_t pos = 0;
    pos = input.find(from.c_str(), pos);
    while (pos != std::string::npos)
    {
        std::string front = input.substr(0, pos) + to.c_str();
        std::string back = input.substr(pos + from.length());
        input = front + back;
        pos += to.length();
        pos = input.find(from.c_str(), pos);
    }
    return input;
}

int connect_to_server(char *address, char *port, fd_set *openSockets, int *maxfds)
{
    struct addrinfo hints, *svr;  // Network host entry for server
    struct sockaddr_in serv_addr; // Socket address for server
    int serverSocket;             // Socket used for server
    int set = 1;                  // Toggle for setsockopt

    hints.ai_family = AF_INET; // IPv4 only addresses
    hints.ai_socktype = SOCK_STREAM;

    memset(&hints, 0, sizeof(hints));

    if (getaddrinfo(address, port, &hints, &svr) != 0)
    {
        perror("getaddrinfo failed: ");
        return -1;
    }

    struct hostent *server;
    server = gethostbyname(address);

    bzero((char *)&serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    bcopy((char *)server->h_addr,
          (char *)&serv_addr.sin_addr.s_addr,
          server->h_length);
    serv_addr.sin_port = htons(atoi(port));

    serverSocket = socket(AF_INET, SOCK_STREAM, 0);

    // Turn on SO_REUSEADDR to allow socket to be quickly reused after
    // program exit.

    if (setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, &set, sizeof(set)) < 0)
    {
        printf("Failed to set SO_REUSEADDR for port %s\n", port);
        perror("setsockopt failed: ");
        return -1;
    }

    if (connect(serverSocket, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
        // EINPROGRESS means that the connection is still being setup. Typically this
        // only occurs with non-blocking sockets. (The serverSocket above is explicitly
        // not in non-blocking mode, so this check here is just an example of how to
        // handle this properly.)
        if (errno != EINPROGRESS)
        {
            printf("Failed to open socket to server: %s\n", port);
            perror("Connect failed: ");
        }
        return -1;
    }

    printf("Server - accept***\n");
    // Add new client to the list of open sockets
    FD_SET(serverSocket, openSockets);

    // And update the maximum file descriptor
    *maxfds = std::max(*maxfds, serverSocket);

    // create a new client to store information.
    Client_Server *new_server = new Client_Server(serverSocket, true);
    new_server->ip = address;
    new_server->port = atoi(port);
    new_server->sent = true;
    all_clients_servers[serverSocket] = new_server;

    // increase number of servers connected
    server_count++;

    // follow protocol and send QUERYSERVERS after new connecton...
    std::string req = "*QUERYSERVERS," + group_name + '#';
    send_message(serverSocket, req);
    return 1;
}

// Close a client's connection, remove it from the client list, and
// tidy up select sockets afterwards.

void closeClient(int socket, fd_set *openSockets, int *maxfds, bool server)
{
    std::cout << "\033[1;31mServer " << all_clients_servers[socket]->name << " left.\033[0m" << std::endl;
    if (server)
    {
        // Remove client from all the map.
        servers_connections.erase(socket);

        server_count--;
    }
    close(socket);

    // And remove from the list of open sockets.
    disconnectedClients.push_back(socket);
    FD_CLR(socket, openSockets);
}

int find_server_to_send_MSG(std::string to_group, int count, std::string msg)
{
    std::cout << "message recived" << std::endl;

    //see if the server that should recive the msg is connecet to us.
    for (auto const &pair : all_clients_servers)
    {
        Client_Server *client = pair.second;
        if (client->name.compare(to_group) == 0)
        {
            std::string msg = "*KEEPALIVE," + std::to_string(count);
            msg += '#';
            std::string response = send_message(pair.first, msg);
            std::cout << response << std::endl;

            return 1;
        }
    }

    for (auto const &pair : servers_connections)
    {
        //run through each server that the servers we are connected to see what server they are connected
        for (auto const &pair2 : pair.second)
        {
            Client_Server *client = pair2.second;
            if (client->name.compare(to_group) == 0)
            {
                std::string msg = "*KEEPALIVE," + std::to_string(count);
                msg += '#';
                std::string response = send_message(pair.first, msg);
                std::cout << response << std::endl;
                return 1;
            }
        }
    }

    std::cout << "Could not find server: " << to_group << "to send" << msg << std::endl;

    return 0;
}

void remove_from_server_connections(std::string name)
{

    std::vector<int> remove_outer;

    for (auto const &pair : all_clients_servers)
    {
        std::cout << "\n";
        std::cout << pair.first << " is connected to:";
        //run through each server that the servers we are connected to see what server they are connected
        for (auto const &pair2 : servers_connections[pair.first])
        {
            std::cout << pair2.first << " ";
            if (pair2.first.compare(name) == 0)
            {
                std::cout << "\n Removed :" << name << " from " << pair.second->name << std::endl;
                remove_outer.push_back(pair.first);
            }
        }
    }
    for (int sock : remove_outer)
    {
        servers_connections[sock].erase(name);
    }
}

void send_connected(int serverSocket, std::string name)
{
    std::string msg = "*CONNECTED," + group_name + "," + server_addr + ',' + port_addr;
    std::set<std::vector<std::string>> all_servers;

    for (auto const &pair : all_clients_servers)
    {
        if (pair.second->server)
        {
            std::vector<std::string> server;
            server.push_back(pair.second->name);
            server.push_back(pair.second->ip);
            server.push_back(std::to_string(pair.second->port));
            all_servers.insert(server);
            // for (auto const &pair2 : servers_connections[pair.first])
            // {
            //     std::vector<std::string> server;
            //     server.push_back(pair2.second->name);
            //     server.push_back(pair2.second->ip);
            //     server.push_back(std::to_string(pair2.second->port));
            //     all_servers.insert(server);
            // }
        }
    }
    for (auto e : all_servers)
    {
        if (!e[0].empty())
        {
            msg += ";" + e[0] + "," + e[1] + "," + e[2];
        }
    }
    msg += "#";
    send_message(serverSocket, msg);
}

void connect_to_server_in_servers_connections(fd_set *openSockets, int *maxfds)
{
    if (server_count < 10)
    {
        bool sent = false;
        std::vector<std::string> remove_servers;
        for (auto const &pair : servers_connections)
        {
            //run through each server that the servers we are connected to see what server they are connected
            for (auto const &pair2 : pair.second)
            {
                //change string to char.
                std::string ip = pair2.second->ip;
                std::string port_str = std::to_string(pair2.second->port);
                char *server_address = new char[ip.length() + 1];
                strcpy(server_address, ip.c_str());
                char *port = new char[port_str.length() + 1];
                strcpy(port, port_str.c_str());
                std::cout << "Ip and port for group " << pair2.first << " are " << ip << " " << port_str << std::endl;
                //try to connect that server that we are not connected to.
                if (connect_to_server(server_address, port, openSockets, maxfds) > 0)
                {
                    //remove that server which we connected to from the map og maps so we  won't try to connect to it again.

                    std::cout << "Sending to server through friends: " << pair2.first << std::endl;
                    std::cout << "Removed in:" << pair.first << std::endl;
                    sent = true;
                }
                remove_servers.push_back(pair2.first);

                if (sent)
                    break;
            }
            if (sent)
                break;
        }
        //remove all the servers that are not answearing, or that we have connected to from friends.
        for (std::string name : remove_servers)
        {
            remove_from_server_connections(name);
        }
    }
}

std::string extract_msg_string(std::string message, int max)
{

    std::string token;
    std::string msg;

    // Split command from client into tokens for parsing
    std::stringstream stream(message);
    int count = 0;
    while (std::getline(stream, token, ','))
    {

        if (count == 2)
        {
            msg += "\033[1;33mFrom :" + token + "\n\033[0m";
        }

        if (count >= max)
        {
            msg += token;
        }
        count += 1;
    }
    msg = msg.substr(0, msg.size() - 1);
    msg = replace(msg, "##", "#");
    msg = replace(msg, "**", "*");
    return msg;
}

std::string extract_msg(char *buffer, int max)
{

    std::string token;
    std::string msg;
    // Split command from client into tokens for parsing
    std::stringstream stream(buffer);
    int count = 0;
    while (std::getline(stream, token, ','))
    {
        if (count >= max)
        {

            msg += token;
        }
        count += 1;
    }
    msg = msg.substr(0, msg.size() - 1);

    return msg;
}

// Process command from client on the server

void clientCommand(int clientSocket, fd_set *openSockets, int *maxfds, std::vector<std::string> tokens, char *buffer)
{
    std::string msg;
    std::string message;
    std::string response;
    if ((tokens[0].compare("CONNECT") == 0) && (tokens.size() == 3))
    {
        char *server_address = new char[tokens[1].length() + 1];
        strcpy(server_address, tokens[1].c_str());
        char *port = new char[tokens[2].length() + 1];
        strcpy(port, tokens[2].c_str());
        connect_to_server(server_address, port, openSockets, maxfds);
    }
    else if (tokens[0].compare("DISCONNECT") == 0)
    {

        if (tokens[1].compare("1") == 0)
        {
            std::string to_group = tokens[2];

            for (auto const &pair : all_clients_servers)
            {
                if (to_group.compare(pair.second->name) == 0)
                {

                    closeClient(pair.first, openSockets, maxfds, true);
                    break;
                }
            }
        }
        else if (tokens[1].compare("2") == 0)
        {
            std::string ip = tokens[2];
            std::string port = tokens[3];
            for (auto const &pair : all_clients_servers)
            {
                if ((ip.compare(pair.second->ip) == 0) && (port.compare(std::to_string(pair.second->port)) == 0))
                {

                    closeClient(pair.first, openSockets, maxfds, true);
                    break;
                }
            }
        }
    }
    else if (tokens[0].compare("LISTSERVERS") == 0)
    {
        msg = "Servers connected to P3_group_1:\n";
        int count = 1;
        for (auto const &pair : all_clients_servers)
        {
            if (pair.second->server && pair.second->name.empty() == false)
            {
                msg += std::to_string(count) + ":" + pair.second->name + "," + pair.second->ip + "," + std::to_string(pair.second->port) + "\n";
                count += 1;
            }
        }
        send(clientSocket, msg.c_str(), msg.length(), 0);
    }
    else if (tokens[0].compare("GETMSG") == 0)
    {
        // get group number
        std::string group = tokens[1];
        // std::cout << tokens[1] << tokens[2] << std::endl;
        if (stored_messages.find(group) != stored_messages.end())
        {
            std::vector<std::string> requested_messages = stored_messages[group];

            if (!requested_messages.empty())
            {
                msg = requested_messages.front();
                requested_messages.erase(requested_messages.begin());
                stored_messages[group] = requested_messages;
                std::string response = send_message(clientSocket, extract_msg_string(msg, 3));
                std::cout << response << std::endl;
            }
        }
    }
    else if (tokens[0].compare("SENDMSG") == 0)
    {
        std::string to_group = tokens[1];
        message = "*SEND_MSG," + to_group + "," + group_name + "," + extract_msg(buffer, 2) + "#";
        stored_messages[to_group].push_back(message);
        int count = stored_messages[to_group].size();

        find_server_to_send_MSG(to_group, count, message);
    }
    else if (tokens[0].compare("SENDALLMSG") == 0)
    {
        std::string extracted_msg = extract_msg(buffer, 1);
        for (auto const &pair : all_clients_servers)
        {

            if (pair.second->server && pair.second->name.empty() == false)
            {
                message = "*SEND_MSG," + pair.second->name + "," + group_name + "," + extracted_msg + "#";
                stored_messages[pair.second->name].push_back(message);
                int count = stored_messages[pair.second->name].size();

                find_server_to_send_MSG(pair.second->name, count, message);
            }
        }
    }
    else if (tokens[0].compare("SENDREQ") == 0)
    {
        std::string to_group = tokens[1];
        message = "*STATUSREQ," + group_name + '#';
        for (auto const &pair : all_clients_servers)
        {
            if (to_group.compare(pair.second->name) == 0)
            {
                response = send_message(pair.first, message);
                std::cout << response << std::endl;
                break;
            }
        }
    }
    else
    {
        msg = "Unknown command from client:" + tokens[0];
        send(clientSocket, msg.c_str(), msg.length(), 0);
        std::cout << msg << std::endl;
    }
}

// Process command from server on the server

void serverCommand(int serverSocket, fd_set *openSockets, int *maxfds, std::vector<std::string> tokens, char *buffer)
{

    if ((tokens[0].compare("QUERYSERVERS") == 0) && (tokens.size() == 2))
    {

        bool multiple = false;
        if (!all_clients_servers[serverSocket]->verified)
        {
            for (auto const &pair : all_clients_servers)
            {
                if ((pair.second->name.compare(tokens[1]) == 0) && (pair.first != serverSocket))
                {
                    std::cout << pair.second->name << tokens[1] << std::endl;
                    std::cout << pair.second->ip << all_clients_servers[serverSocket]->ip << std::endl;
                    std::cout << pair.second->port << all_clients_servers[serverSocket]->port << std::endl;
                    std::cout << "Tryed to connect ot us again" << tokens[1] << std::endl;
                    closeClient(serverSocket, openSockets, maxfds, true);
                    multiple = true;
                }
            }
        }
        if (!multiple)
        {
            //if he has not been verifyed, we varify the server and set his name.
            if (!all_clients_servers[serverSocket]->verified)
            {
                all_clients_servers[serverSocket]->name = tokens[1];
                all_clients_servers[serverSocket]->verified = true;
            }

            //if we have not sent queryserver before we send it queryserver back.
            if (!all_clients_servers[serverSocket]->sent)
            {
                all_clients_servers[serverSocket]->sent = true;
                std::string req = "*QUERYSERVERS," + group_name + '#';
                send_message(serverSocket, req);
            }

            //this is for when we are portfowrading and don't know our serveraddress.
            if (server_addr.compare("0.0.0.0") != 0)
            {

                send_connected(serverSocket, tokens[1]);
            }
        }
    }
    //check if the servers has sent first QUERYSERVERS
    else if (all_clients_servers[serverSocket]->verified)
    {

        if ((tokens[0].compare("CONNECTED") == 0) && (tokens.size() % 3 == 1))
        {
            bool multiple = false;
            if (!all_clients_servers[serverSocket]->verified)
            {
                for (auto const &pair : all_clients_servers)
                {
                    if ((pair.second->ip.compare(tokens[2]) == 0) && (pair.second->port == atoi(tokens[3].c_str())) && (pair.first != serverSocket))
                    {
                        std::cout << pair.second->name << tokens[1] << std::endl;
                        std::cout << pair.second->ip << all_clients_servers[serverSocket]->ip << std::endl;
                        std::cout << pair.second->port << all_clients_servers[serverSocket]->port << std::endl;
                        std::cout << "Tryed to connect ot us again" << tokens[1] << std::endl;
                        closeClient(serverSocket, openSockets, maxfds, true);
                        multiple = true;
                    }
                }
            }
            if (!multiple)
            {
                //if we have not still found the server address, we can access it now and send queryservice.
                if (server_addr.compare("0.0.0.0") == 0)
                {
                    for (int i = 1; i <= (((int)tokens.size() - 4) / 3); i++)
                    {

                        if (group_name.compare(tokens[(3 * i) + 1]) == 0)
                        {
                            server_addr = tokens[(3 * i) + 2];
                        }
                    }
                    send_connected(serverSocket, tokens[1]);
                }
                //if the server has the wrong name
                all_clients_servers[serverSocket]->port = atoi(tokens[3].c_str());

                std::map<std::string, Client_Server *> server_servers;
                bool skip = false;

                //let's itterrate through all the servers that we were sent with the CONNECTED command.
                for (int i = 1; i <= (((int)tokens.size() - 4) / 3); i++)
                {
                    std::string name = tokens[(i * 3) + 1];
                    std::string port = tokens[(i * 3) + 3];
                    std::string address = tokens[(i * 3) + 2];
                    //let's check if we are also connected to him, if we are we don't add him to the map of the servers that are connected to the server who sent this.
                    for (auto const &pair : all_clients_servers)
                    {
                        if ((pair.second->name.compare(name) == 0) || (pair.second->ip.compare(address) == 0 && std::to_string(pair.second->port).compare(port) == 0))
                        {
                            skip = true;
                            break;
                        }
                    }

                    //check if server has same name as this server, if it has it we are not intrested adding it to server_connections,
                    // if server has same address and  same port, we are not intrested adding it too.
                    //if server is skiped,(server is connected ), we are not interested adding it too
                    if (group_name.compare(name) != 0 && (!(server_addr.compare(address) == 0 && port_addr.compare(port) == 0)) && !skip)
                    {
                        Client_Server *new_server = new Client_Server(serverSocket, true);
                        std::string name = tokens[(i * 3) + 1];
                        new_server->name = name;
                        new_server->ip = tokens[(3 * i) + 2];
                        new_server->port = atoi(tokens[(3 * i) + 3].c_str());
                        server_servers[name] = new_server;
                        std::cout << "server name: " << new_server->name << " is connected to " << serverSocket << std::endl;
                    }
                    skip = false;
                }
                servers_connections[serverSocket] = server_servers;
            }
        }
        else if ((tokens[0].compare("KEEPALIVE") == 0) && (tokens.size() == 2))
        {
            int message_count = atoi(tokens[1].c_str());
            if (message_count > 0)
            {
                std::string request = "*GET_MSG," + group_name + "#";
                std::string response = send_message(serverSocket, request);
                std::cout << response << std::endl;
            }
        }
        else if ((tokens[0].compare("GET_MSG") == 0) && (tokens.size() == 2))
        {
            // get group number
            std::string group = tokens[1];
            // std::cout << tokens[1] << tokens[2] << std::endl;
            if (stored_messages.find(group) != stored_messages.end())
            {
                std::vector<std::string> requested_messages = stored_messages[group];
                for (std::string request : requested_messages)
                {

                    std::string response = send_message(serverSocket, request);
                    log_to_file("sent: " + request);
                    std::cout << response << std::endl;
                }
                std::vector<std::string> empty;
                stored_messages[group] = empty;
            }
        }
        //if server recives SEND_MSG cammnd enter this if clause.
        else if ((tokens[0].compare("SEND_MSG") == 0) && (tokens.size() > 3))
        {
            // send_message(serverSocket,"Message recived.");

            std::string to_group = tokens[1];
            std::string msg = buffer;
            stored_messages[to_group].push_back(msg);
            int count = stored_messages[to_group].size();

            //check if msg is for us or not.
            if (to_group.compare(group_name) == 0)
            {
                std::cout << "we received a msg" << std::endl;
                log_to_file("received: " + msg);
            }
            else
            {
                find_server_to_send_MSG(to_group, count, msg);
            }
        }
        else if (tokens[0].compare("LEAVE") == 0)
        {
            closeClient(serverSocket, openSockets, maxfds, true);
        }
        else if ((tokens[0].compare("STATUSREQ") == 0) && (tokens.size() == 2))
        {
            //let's create a statusresponse.
            std::string from_group = tokens[1];
            std::string message = "*STATUSRESP," + group_name + ',' + from_group;

            //itterate through all the servers we have\had messages for.
            for (auto const &pair : stored_messages)
            {
                std::string group = pair.first;
                int message_count = pair.second.size();
                //if they are not empty we add thir name and the amount to the response.
                if (!group.empty())
                {
                    message += ',' + group + ',' + std::to_string(message_count);
                }
            }
            message += '#';
            std::string response = send_message(serverSocket, message);
            std::cout << response << std::endl;
        }
        else if (tokens[0].compare("STATUSRESP") == 0)
        {

            //let's iterrate through all the servers that we were sent with the STATUSRESP command.
            for (int i = 1; i <= (((int)tokens.size() - 2) / 2); i++)
            {
                // get the name of the group and the number of messages
                std::string group = tokens[(i * 2) + 1];
                int message_count = atoi(tokens[(i * 2) + 2].c_str());

                //we send get_msg if the count is larger then 0.

                if (message_count > 0)
                {
                    //let's check if we are also connected to him. If we are we, request the message and store it so it will be sent automatically later
                    for (auto const &pair : all_clients_servers)
                    {
                        if ((pair.second->name.compare(group) == 0))
                        {
                            std::string request = "*GET_MSG," + group + "#";
                            std::string response = send_message(serverSocket, request);
                        }
                    }
                    //also check all servers that are connected to servers that are connect to us..
                    for (auto const &pair : servers_connections)
                    {
                        //run through each server that the servers we are connected to see what server they are connected
                        for (auto const &pair2 : pair.second)
                        {
                            if ((pair2.second->name.compare(group) == 0))
                            {

                                std::string request = "*GET_MSG," + group + "#";
                                std::string response = send_message(serverSocket, request);
                            }
                        }
                    }
                }
            }
        }
        else
        {

            std::cout << "Unknown command from server:" << buffer << std::endl;
        }
    }
    else
    {

        std::cout << "Unverified server" << buffer << std::endl;
    }
}

//split the buffer on commas and semicommas into tokens.
std::vector<std::string> tokenize_command(char *buffer)
{
    std::vector<std::string> tokens;
    std::string token;
    std::string mini;
    std::string buf = replace((std::string) buffer,";,","; ,");
    buf = replace((std::string) buf,",,",", ,");
    buf = replace((std::string) buf,",;",",;");
    // Split command from client into tokens for parsing
    std::stringstream stream(buf.c_str());



    int count = 0;
    while (std::getline(stream, token, ','))
    {
        //check if there is star in the begining of the command.
        if (count == 0)
        {
            char firstletter = token.front();
            if (firstletter == '*')
            {
                token = token.substr(1);
                ;
            }
        }


        std::stringstream ss(token);
        while (std::getline(ss, mini, ';'))
        {
            //remove whtiespace
            mini.erase(std::remove_if(mini.begin(), mini.end(), ::isspace), mini.end());
            tokens.push_back(mini);
        }
    }

    //check if the last letter is #
    char lastletter = token.back();

    if (lastletter == '#')
    {

        token = tokens.back();
        tokens.pop_back();

        token = token.substr(0, token.size() - 1);
        tokens.push_back(token);
    }

    if (tokens.back().empty())
    {

        tokens.pop_back();
    }

    return tokens;
}

//send keepalive too all the servers we re conneceted to.
void send_keepalive()
{

    while (true)
    {
        for (auto const &pair : all_clients_servers)
        {
            //check if the connetion is server.
            if (pair.second->server)
            {
                std::vector<std::string> messages = stored_messages[pair.second->name];
                std::string msg = "*KEEPALIVE," + std::to_string(messages.size()) + "#";
                send_message(pair.first, msg);
            }
        }
        sleep(180);
    }
}

//we wan't to keep serverconections list up to date so we send queryservers to all the servers we are connected.
void send_queryservers()
{

    while (true)
    {
        for (auto const &pair : all_clients_servers)
        {
            //check if the connetion is server.
            if (pair.second->server)
            {
                std::string msg = "*QUERYSERVERS," + group_name + '#';
                send_message(pair.first, msg);
            }
        }
        //we don't want to spamm this request, maybe every 10 min.
        sleep(1800);
    }
}

int main(int argc, char *argv[])
{
    bool finished;
    int clientListenSock;              // Socket for client connections to server
    int clientSock;                    // Socket of connecting client
    int serverListenSock;              // Socket for server connections to server
    int serverSock;                    // Socket of connecting server
    fd_set openSockets;                // Current open sockets
    fd_set readSockets;                // Socket list for select()
    fd_set exceptSockets;              // Exception socket list
    int maxfds;                        // Passed to select() as max fd in set
    struct sockaddr_in new_connection; // The sockaddr of any new client/server
    socklen_t connectionLen;           // The length of  new_connection
    char buffer[1000];                 // buffer for reading from clients
    char bytestuffBuffer[1000];        // actual message, the data from buffer until the first single hashtag
    port_addr = argv[1];               // the port address to run on
    bool foundHashtag;                 // Variable used in while loop to read from buffer, we read until a single hashtag is found
    size_t off;
    char next;
    std::string pendingRequest; // if a message exeeds the buffer size, we store the message in this variable until the full message is read
    bool pending;               // this variable indicates whether there is some data in the pendingRequest variable
    time_t time1;
    time_t time2;



    if (argc != 2)
    {
        printf("Usage: chat_server <ip port>\n");
        exit(0);
    }

    // Setup client socket for server to listen to

    clientListenSock = open_socket(atoi(argv[1]) - 1);
    printf("Listening for client connections on port: %d\n", atoi(argv[1]) - 1);

    if (listen(clientListenSock, BACKLOG) < 0)
    {
        printf("Client_Server listening failed on port %d\n", atoi(argv[1]) - 1);
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

    std::thread keepalive_thread(send_keepalive);
    std::thread queryservers_thread(send_queryservers);
    // std::thread find_other_servers(connect_to_server_in_servers_connections, &openSockets, &maxfds);

    finished = false;
    time(&time1);

    while (!finished)
    {

        // Get modifiable copy of readSockets
        readSockets = exceptSockets = openSockets;
        memset(buffer, 0, sizeof(buffer));
        memset(bytestuffBuffer, 0, sizeof(bytestuffBuffer));

        // Look at sockets and see which ones have something to be read()
        int n = select(maxfds + 1, &readSockets, NULL, &exceptSockets, NULL);

        //check if the time has been moer then 180 s since we last send a new req.
        time(&time2);
        if (difftime(time2, time1) > 180)
        {

            connect_to_server_in_servers_connections(&openSockets, &maxfds);
            time(&time1);
        }
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
                clientSock = accept(clientListenSock, (struct sockaddr *)&new_connection,
                                    &connectionLen);
                printf("Client - accept***\n");
                // Add new client to the list of open sockets
                FD_SET(clientSock, &openSockets);

                // And update the maximum file descriptor
                maxfds = std::max(maxfds, clientSock);
                std::cout << new_connection.sin_port << std::endl;
                // create a new client to store information.
                all_clients_servers[clientSock] = new Client_Server(clientSock, false);

                // Decrement the number of sockets waiting to be dealt with
                n--;

                printf("\033[1;32mClient connected on server: %d \033[0m\n", clientSock);
            }
            // Next, accept  any new server connections to the server on the server listening socket
            if (FD_ISSET(serverListenSock, &readSockets) && (server_count < 16))
            {
                serverSock = accept(serverListenSock, (struct sockaddr *)&new_connection,
                                    &connectionLen);
                printf("Server - accept***\n");
                // Add new client to the list of open sockets
                FD_SET(serverSock, &openSockets);

                // And update the maximum file descriptor
                maxfds = std::max(maxfds, serverSock);

                char ip_str[INET_ADDRSTRLEN];
                // now get it back and print it
                inet_ntop(AF_INET, &(new_connection.sin_addr), ip_str, INET_ADDRSTRLEN);
                std::cout << ip_str << std::endl;
                // create a new client to store information.
                Client_Server *new_server = new Client_Server(serverSock, true);
                new_server->ip = ip_str;
                std::cout << ip_str << std::endl;
                new_server->port = -1;
                all_clients_servers[serverSock] = new_server;

                // increase number of servers connected
                server_count++;

                // Decrement the number of sockets waiting to be dealt with
                n--;

                printf("\033[1;32mServer connected on server: %d \033[0m", serverSock);
            }
            // Now check for commands from all_clients_servers
            disconnectedClients.clear();
            while (n-- > 0)
            {

                pendingRequest = "";
                for (auto const &pair : all_clients_servers)
                {
                    // client can be both client and server, more conveniient to use same name
                    Client_Server *client = pair.second;

                    if (FD_ISSET(client->sock, &readSockets))
                    {
                        // recv() == 0 means client has closed connection
                        if (recv(client->sock, buffer, sizeof(buffer), MSG_PEEK | MSG_DONTWAIT) == 0)
                        {
                            std::cout << "\033[1;31mClient/Server closed connection: \033[0m" << client->sock << std::endl;

                            closeClient(client->sock, &openSockets, &maxfds, client->server);
                        }
                        // We don't check for -1 (nothing received) because select()
                        // only triggers if there is something on the socket for us.
                        else
                        {
                            // memset(buffer, 0, sizeof(buffer));

                            // printf("\033[1;32mFrom Whole buffer:\n\033[0m'%s'\n", buffer);
                            off = 0;
                            foundHashtag = false;
                            char *p;
                            if (!pending)
                            {
                                // if there is no data pending, we erase the request variable
                                pendingRequest = "";
                            }

                            pending = false;
                            // we read the buffer until a single hashtag is found
                            while (!foundHashtag)
                            {

                                p = strchr(buffer + off, '#');

                                // bytestuffing...
                                if (p == NULL)
                                {
                                    pending = true;
                                    foundHashtag = true;
                                }
                                else
                                {
                                    next = *(p + 1);

                                    if (next != '#')
                                    {
                                        foundHashtag = true;
                                    }
                                    else
                                    {
                                        p += 2;
                                        off = p - buffer;
                                    }
                                }
                            }

                            if (p != NULL)
                            {
                                // copy everything until the first hashtag
                                recv(client->sock, bytestuffBuffer, p - buffer + 1, MSG_DONTWAIT);
                            }
                            else
                            {
                                // if there is no hashtag, copy the whole buffer and keep reding. This happens when the message is longer than the buffer
                                recv(client->sock, bytestuffBuffer, sizeof(bytestuffBuffer), MSG_DONTWAIT);
                            }

                            //printf("byteBuff '%s'\n", bytestuffBuffer);

                            pendingRequest.append(bytestuffBuffer);

                            // if the whole message has been read
                            if (!pending)
                            {
                                char *long_req = new char[pendingRequest.length() + 1];

                                strcpy(long_req, pendingRequest.c_str());

                                std::vector<std::string> tokens = tokenize_command(long_req);
                                std::cout << "\033[1;32mFrom " << all_clients_servers[client->sock]->name << " number: " << std::to_string(client->sock) << " We recived : \033[0m" << std::endl;
                                printf("'%s'\n", long_req);
                                if (client->server)
                                {
                                    // if the request is from a server we process it as a server command
                                    serverCommand(client->sock, &openSockets, &maxfds, tokens, long_req);
                                }
                                else
                                {
                                    // if the request is from a client we process it as a client command
                                    clientCommand(client->sock, &openSockets, &maxfds, tokens, long_req);
                                }
                                break;
                            }
                        }
                    }
                }
                bool removed_max = false;
                // Remove client from the clients list
                for (auto const &c : disconnectedClients)
                {
                    all_clients_servers.erase(c);
                    if (maxfds == c)
                    {
                        removed_max = true;
                    }
                }

                if (removed_max)
                {
                    // If this client's socket is maxfds then the next lowest
                    // one has to be determined. Socket fd's can be reused by the Kernel,
                    // so there aren't any nice ways to do this.

                    maxfds = 4;
                    for (auto const &p : all_clients_servers)
                    {
                        maxfds = std::max(maxfds, p.second->sock);
                    }
                }
                break;
            }
        }
    }
}
