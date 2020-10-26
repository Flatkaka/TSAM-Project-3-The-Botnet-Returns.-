PROJECT 3, TSAM
------------------------------------------------------------------

Our solution to project 3 is in two separarte files, client.cpp and
server.cpp

------------------------------------------------------------------
To compile and run the code, follow the instructioins below
------------------------------------------------------------------

To comepile client.cpp and server.cpp, write "make" into the 
commandline

        make

To run client, type in the command below. The client takes in two arguments,
the IP address and port which you want to connect to. We implemented a few extra commands
on the client that the server can respond to. The commands are: CONNECT, DISCONNECT, 
SENDALLMSG and STATUSREQ. All parameters should follow the commands separated by comma.
 CONNECT is used to make the connected server connect to another server,
it takes two parameters, the IP address and port of the server to connect to.
DISCONNECT is used to make the server diconnect from another servers, it can be used in two ways,
if the first parameter is 1, then the next parameter should be the name of the server to disconnect from.
If the first parameter 2 however, the IP and port of the server to disconnect from should follow.
SENDALLMSG s used to send messages to all connected servers, the message should follow the command
after a comma. Finally, STATUSREQ is used to send status requests to another server, the name of the server
is the only parameter.

        ./client <P_address> <port>

To run the server you need to write the command below.
The program takes in two arguments, the port number where the server accepts
connections from other servers. The server then accpets client connections at port
below the supplied port. The second parameter, home/skel, can be either 1 or 0.
If 1, then the server can run with port forwardinig and seeks it external IP address
from the first CONNECTED message. If 0, the server can be run on skel and gets its
IP address from the getIP() function. When the server is run behind a port forward, 1, 
it is best to connect a client to it and the use the client to make the server connect
to another server (CONNECT command) right away so the server can get its IP address
as early as possible. We often ran the server both at skel and homee at the same time, 
then the name of the group at skel was 'P3_GROUP_1' and the one at home was 'P3_GROUP_1_home'.
Hence, when the name 'P3_GROUP_1_home' appeared on any instructor server, oracle or number station,
it was from our server behind NAT.

       ./tsamgroup1 <port> <home/skel>


------------------------------------------------------------------
Author: Hilmar Páll Stefánsson and Kristján Ari Tómasson
------------------------------------------------------------------

Hilmar Pall Stefansson.
and
Kristjan Ari Tomasson