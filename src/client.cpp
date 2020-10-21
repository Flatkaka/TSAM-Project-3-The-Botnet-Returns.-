//
// Simple chat client for TSAM-409
//
// Command line: ./chat_client 4000
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
#include <thread>

#include <time.h>

#include <iostream>
#include <sstream>
#include <thread>
#include <map>

// Threaded function for handling responss from server

void listenServer(int serverSocket, struct tm *timeinfo)
{
    int nread;         // Bytes read from socket
    char buffer[1025]; // Buffer for reading input

    while (true)
    {
       memset(buffer, 0, sizeof(buffer));
       nread = read(serverSocket, buffer, sizeof(buffer));

       if(nread == 0)                      // Server has dropped us
       {
          printf("Over and Out\n");
          exit(0);
       }
       else if(nread > 0)
       {
          std::cout<<"\033[1;32mAt "<< asctime(timeinfo) <<"We recived : \033[0m"<<std::endl;
          printf("%s\n", buffer);
       }
    }
}

std::string replace(std::string input, std::string from, std::string to)
{
    size_t pos = 0;
    pos = input.find(from.c_str(), pos);
    while (pos != std::string::npos)
    {
        input.replace(pos, sizeof(to.c_str()), to.c_str());
        pos += sizeof(to.c_str());
        pos = input.find(from.c_str(), pos);
    }
    return input;
}

int main(int argc, char *argv[])
{
    struct addrinfo hints, *svr;  // Network host entry for server
    struct sockaddr_in serv_addr; // Socket address for server
    int serverSocket;             // Socket used for server
    int nwrite;                   // No. bytes written to server
    char buffer[1025];            // buffer for writing to server
    bool finished;
    int set = 1; // Toggle for setsockopt
    time_t rawtime;
    struct tm *timeinfo;
    time(&rawtime);
    timeinfo = localtime(&rawtime);

    if (argc != 3)
    {
        printf("Usage: chat_client <ip  port>\n");
        printf("Ctrl-C to terminate\n");
        exit(0);
    }

    hints.ai_family = AF_INET; // IPv4 only addresses
    hints.ai_socktype = SOCK_STREAM;

    memset(&hints, 0, sizeof(hints));

    if (getaddrinfo(argv[1], argv[2], &hints, &svr) != 0)
    {
        perror("getaddrinfo failed: ");
        exit(0);
    }

    struct hostent *server;
    server = gethostbyname(argv[1]);

    bzero((char *)&serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    bcopy((char *)server->h_addr,
          (char *)&serv_addr.sin_addr.s_addr,
          server->h_length);
    serv_addr.sin_port = htons(atoi(argv[2]));

    serverSocket = socket(AF_INET, SOCK_STREAM, 0);

    // Turn on SO_REUSEADDR to allow socket to be quickly reused after
    // program exit.

    if (setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, &set, sizeof(set)) < 0)
    {
        printf("Failed to set SO_REUSEADDR for port %s\n", argv[2]);
        perror("setsockopt failed: ");
    }

    if (connect(serverSocket, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
        // EINPROGRESS means that the connection is still being setup. Typically this
        // only occurs with non-blocking sockets. (The serverSocket above is explicitly
        // not in non-blocking mode, so this check here is just an example of how to
        // handle this properly.)
        if (errno != EINPROGRESS)
        {
            printf("Failed to open socket to server: %s\n", argv[1]);
            perror("Connect failed: ");
        }
        exit(0);
    }

    // Listen and print replies from server
    std::thread serverThread(listenServer, serverSocket, timeinfo);

    finished = false;
    std::string args_from_user;

    while (!finished)
    {
        bzero(buffer, sizeof(buffer));
        getline(std::cin, args_from_user);
        while (args_from_user.compare("") == 0)
        {
            getline(std::cin, args_from_user);
        }

        args_from_user.substr(0, args_from_user.size()-1);
        args_from_user = replace(args_from_user, "*", "**");
        args_from_user = replace(args_from_user, "#", "##");
        args_from_user="*"+args_from_user+"#";
        std::cout<<"\033[1;32mAt "<< asctime(timeinfo) <<"We sent : \033[0m"<<std::endl;
        printf("%s\n", args_from_user.c_str());
        strcpy(buffer, args_from_user.c_str());


        nwrite = send(serverSocket, args_from_user.c_str(), args_from_user.length(), 0);

        if (nwrite == -1)
        {
            perror("send() to server failed: ");
            finished = true;
        }
    }
}
