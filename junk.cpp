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
            tokens.push_back(mini);
        }
        
    }

    return tokens;
}

int main(int argc, char *argv[]){

    std::vector<std::string> tokens= get_message(argv[1]);
    std::cout<<tokens.size()<<std::endl;
    std::cout<<((tokens.size()-4)/3)<<std::endl;
    for (int i =1;i <= ((tokens.size()-4)/3);i++){
        std::cout<< i<<std::endl;
        std::cout<< tokens[(3*i)+1]<<std::endl;

    }
}