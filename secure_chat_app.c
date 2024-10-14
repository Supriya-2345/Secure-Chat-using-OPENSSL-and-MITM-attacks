// Import the required header files
#include<stdio.h>           // for printf()
#include<string.h>          // for bzero()
#include<stdbool.h>         // for bool data type
#include<netdb.h>           // for gethostbyname()
#include<arpa/inet.h>       // for inet_addr()
#include<stdlib.h>          // for exit()
#include<unistd.h>          // for close()
#include<sys/time.h>        // for struct timeval
#include<openssl/ssl.h>     // for SSL algorithms
#include<openssl/err.h>     // for SSL errors
#include<openssl/bio.h>     // for SSL BIO
#include<fcntl.h>           // for fcntl()
#include<sys/select.h>      // for select()

// Define the required macros
#define MAX_LENGTH 1024     // define the buffer length
#define PORT 8001           // define the server port
#define SECRET_LENGTH 100   // define the maximum cookie length
#define INF 99999           // define the maximum wait length of a socket

// Define the required global variables and data types
char error[100], host[10], peer[10];
typedef enum role{server, client} role;

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
Name        :   chatSSL()
Description :   Defines the procedure for the peers to chat with each other through a secure network.
Arguments   :   Pointer to the SSL connection
Return      :   None
**/
void chatSSL(SSL *connection) {

    // Declare the required local variables
    char buffer[MAX_LENGTH];
    bool keepAlive = true;
    int length, max_fd, socketFD = SSL_get_fd(connection);
    struct timeval timeout = {2, 0};
    fd_set rfds;

    // Set the me and peer host names
    if(strcmp(host, "alice1") == 0)
        strcpy(peer, "Bob");
    else
        strcpy(peer, "Alice");
    
    // Notify the user to start the chat
    printf("Start the chat\n");

    // Begin the chat loop
    while(keepAlive) {

        // Create the FD set instance and add SSL socket and STDIN to it
        FD_ZERO(&rfds);
        FD_SET(socketFD, &rfds);
        FD_SET(STDIN_FILENO, &rfds);
        max_fd = socketFD > STDIN_FILENO ? socketFD : STDIN_FILENO;

        // Wait for an event to occur on any of the sockets
        int ret = select(max_fd + 1, &rfds, NULL, NULL, NULL);
        if (ret < 0) {
            sprintf(error, "Select error\n");
            perror(error);
            exit(EXIT_FAILURE);
        }

        // Check if any data is available on the SSL Socket
        if(FD_ISSET(socketFD, &rfds)) {

            // Read the data from SSL socket
            bzero(buffer, sizeof(buffer));
            length = SSL_read(connection, buffer, sizeof(buffer));
            buffer[length] = '\0';
            
            // Handle the chat close request from the peer
            if(strcmp(buffer, "chat_close") == 0) {
                
                // Notify the user about the chat close
                printf("%s closed the chat.\n", peer);
                
                // Send the chat_close_ACK acknowledgement
                chat_close_ACK_server:

                    bzero(buffer, sizeof(buffer));
                    strcpy(buffer, "chat_close_ACK");
                    SSL_write(connection, buffer, sizeof(buffer));

                // Set the socket to listen for 2 seconds
                setsockopt(socketFD, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
                bzero(buffer, sizeof(buffer));
                length = SSL_read(connection, buffer, sizeof(buffer));

                // If any any data received again, resend chat_close_ACK acknowledgement
                buffer[length] = '\0';
			    if(strcmp(buffer, "chat_close") == 0)
                    goto chat_close_ACK_server;
                            
                // Break the chat loop
                keepAlive = false;
                continue;
            }

            // Handle the abrupt closing of the chat
            else if(strcmp(buffer, "chat_close_ACK") == 0) {
                keepAlive = false;
                continue;
            }

            // In case of an normal message, print the message on the console
            else if(strlen(buffer) > 0)
                printf("%s: %s\n", peer, buffer);
        
        }

        // Check if any data is available on the STDIN
        if(FD_ISSET(STDIN_FILENO, &rfds)) {

            // Read the data from STDIN
            bzero(buffer, sizeof(buffer));
            length = read(STDIN_FILENO, buffer, sizeof(buffer));
            buffer[length - 1] = '\0';

            // Handle the chat close command from the user
            if(strcmp(buffer, "exit") == 0) {

                // Send the chat_close control message
                chat_close:
                    bzero(buffer, sizeof(buffer));
                    strcpy(buffer, "chat_close");
                    SSL_write(connection, buffer, sizeof(buffer));

                // Set the socket to listen for 2 seconds
                setsockopt(socketFD, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
                bzero(buffer, sizeof(buffer));
                length = SSL_read(connection, buffer, sizeof(buffer));

                // If chat_close_ACK not received, resend chat_close
                if(length <= 0)
                    goto chat_close;
                            
                // Break the chat loop
                keepAlive = false;
                continue;
            }

            // In case of a normal message, send the message through the SSL socket
            else if(strlen(buffer) > 0)
                SSL_write(connection, buffer, sizeof(buffer));
        }
    }
    return;
}

/**
Name        :   chatSocket()
Description :   Defines the procedure for the peers to chat with each other through an unsecure network.
Arguments   :   Socket Descriptor and the address of the peer, in that order
Return      :   None
**/
void chatSocket(int socketFD, struct sockaddr_in peerAddress) {

    // Declare the required local variables
    char buffer[MAX_LENGTH];
    bool keepAlive = true;
    int length, max_fd, peerLength = sizeof(peerAddress);
    struct timeval timeout = {2, 0};
    fd_set rfds;

    // Set the me and peer host names
    if(strcmp(host, "alice1") == 0)
        strcpy(peer, "Bob");
    else
        strcpy(peer, "Alice");
    
    // Notify the user to start the chat
    printf("Start the chat\n");

    // Begin the chat loop
    while(keepAlive) {

        // Create an FD set instance and add the UDP socket and STDIN to it
        FD_ZERO(&rfds);
        FD_SET(socketFD, &rfds);
        FD_SET(STDIN_FILENO, &rfds);
        max_fd = socketFD > STDIN_FILENO ? socketFD : STDIN_FILENO;

        // Wait for an event to occur on any of the sockets
        int ret = select(max_fd + 1, &rfds, NULL, NULL, NULL);
        if (ret < 0) {
            sprintf(error, "Select error\n");
            perror(error);
            exit(EXIT_FAILURE);
        }

        // Check if any data is available on the UDP socket
        if(FD_ISSET(socketFD, &rfds)) {

            // Read the data from UDP socket
            bzero(buffer, sizeof(buffer));
            length = recvfrom(socketFD, buffer, sizeof(buffer), 0, (struct sockaddr*)&peerAddress, &peerLength);
            buffer[length] = '\0';

            // Handle the chat close request from the peer
            if(strcmp(buffer, "chat_close") == 0) {
                
                // Notify the user about the chat close
                printf("%s closed the chat.\n", peer);
                
                // Send the chat_close_ACK acknowledgement 
                chat_close_ACK_server:

                    bzero(buffer, sizeof(buffer));
                    strcpy(buffer, "chat_close_ACK");
                    sendto(socketFD, buffer, sizeof(buffer), 0, (struct sockaddr*)&peerAddress, peerLength);

                // Set the socket to listen for 2 seconds
                setsockopt(socketFD, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
                bzero(buffer, sizeof(buffer));
                length = recvfrom(socketFD, buffer, sizeof(buffer), 0, (struct sockaddr*)&peerAddress, &peerLength);

                // If any any data received again, resend chat_close_ACK acknowledgement
                buffer[length] = '\0';
			    if(strcmp(buffer, "chat_close") == 0)
                    goto chat_close_ACK_server;
                            
                // Break the chat loop
                keepAlive = false;
                continue;
            }

            // Handle the abrupt closing of the chat
            else if(strcmp(buffer, "chat_close_ACK") == 0) {
                keepAlive = false;
                continue;
            }

            // In case of an normal message, print the message on the console
            else if(strlen(buffer) > 0)
                printf("%s: %s\n", peer, buffer);
        }

        // Check if any data is available on the STDIN
        if(FD_ISSET(STDIN_FILENO, &rfds)) {

            // Read the data from STDIN
            bzero(buffer, sizeof(buffer));
            length = read(STDIN_FILENO, buffer, sizeof(buffer));
            buffer[length - 1] = '\0';

            // Handle the chat close command from the user
            if(strcmp(buffer, "exit") == 0) {

                // Send the chat_close control message
                chat_close:
                    bzero(buffer, sizeof(buffer));
                    strcpy(buffer, "chat_close");
                    sendto(socketFD, buffer, sizeof(buffer), 0, (struct sockaddr*)&peerAddress, peerLength);

                // Set the socket to listen for 2 seconds
                setsockopt(socketFD, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
                bzero(buffer, sizeof(buffer));
                length = recvfrom(socketFD, buffer, sizeof(buffer), 0, (struct sockaddr*)&peerAddress, &peerLength);

                // If chat_close_ACK not received, resend chat_close
                if(length <= 0)
                    goto chat_close;
                            
                // Break the chat loop
                keepAlive = false;
                continue;
            }

            // In case of a normal mesage, send it through the UDP socket
            else if(strlen(buffer) > 0)
                sendto(socketFD, buffer, sizeof(buffer), 0, (struct sockaddr*)&peerAddress, peerLength);
        }
    }
    return;
}

/**
Name        :   asServer()
Description :   Defines the procedure for connection setup on the server side before the chat.
Arguments   :   None
Return      :   None
**/
void asServer() {
    
    // Declare the required local variables
    char buffer[MAX_LENGTH], ip[20];
    int socketFD, clientLength, messageLength, status, flag;
    struct sockaddr_in serverAddress, clientAddress;
    const unsigned char cookie[SECRET_LENGTH];
    unsigned int length;
    struct timeval timeout = {5, 0};
    
    // Try creating a Server Socket and print appropriate message
    bzero(&serverAddress, sizeof(serverAddress));
    if((socketFD = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        bzero(error, sizeof(error));
        sprintf(error, "Socket creation failed.\n");
        perror(error);
        exit(EXIT_FAILURE);
    }
    
    // Prepare the server address details for binding
    retrieveIP(host, ip);
    serverAddress.sin_addr.s_addr = inet_addr(ip);
    serverAddress.sin_port = htons(PORT);
    serverAddress.sin_family = AF_INET;
    memset(&(serverAddress.sin_zero), '\0', 8);
    
    // Try binding the server address to the Socket and print appropriate message
    if(bind(socketFD, (struct sockaddr*)&serverAddress, sizeof(struct sockaddr_in)) < 0) {
        bzero(error, sizeof(error));
        sprintf(error, "Socket binding failed.\n");
        perror(error);
        close(socketFD);
        exit(EXIT_FAILURE);
    }

    // Receive chat_hello from the client
    bzero(buffer, sizeof(buffer));
    clientLength = sizeof(clientAddress);
    if((messageLength = recvfrom(socketFD, buffer, sizeof(buffer), 0, (struct sockaddr*)&clientAddress, &clientLength)) == -1) {
        bzero(error, sizeof(error));
        sprintf(error, "Listening from client failed.\n");
        perror(error);
        close(socketFD);
        exit(EXIT_FAILURE);
    }
    buffer[messageLength] = '\0';

    // Send chat_ok_reply to the client
    chat_ok_reply:
        bzero(buffer, sizeof(buffer));
        sprintf(buffer, "chat_ok_reply");
        if(sendto(socketFD, buffer, sizeof(buffer), 0, (struct sockaddr*)&clientAddress, clientLength) == -1) {
            bzero(error, sizeof(error));
            sprintf(error, "Replying to client failed.\n");
            perror(error);
            close(socketFD);
            exit(EXIT_FAILURE);
        }

    // Read data from the socket
    bzero(buffer, sizeof(buffer));
    messageLength = recvfrom(socketFD, buffer, sizeof(buffer), 0, (struct sockaddr*)&clientAddress, &clientLength);
    buffer[messageLength] = '\0';

    // Handle packet loss of chat_ok_reply
    if(strcmp(buffer, "chat_hello") == 0)
        goto chat_ok_reply;
    
    // Handle SSL_NOT_SUPPORTED case
    if(strcmp(buffer, "chat_START_SSL_NOT_SUPPORTED") == 0) {
        
        // Send the chat_START_SSL_NOT_SUPPORTED_ACK control message
        chat_START_SSL_NOT_SUPPORTED_ACK:
            bzero(buffer, sizeof(buffer));
            sprintf(buffer, "chat_START_SSL_NOT_SUPPORTED_ACK");
            if(sendto(socketFD, buffer, sizeof(buffer), 0, (struct sockaddr*)&clientAddress, clientLength) == -1) {
                bzero(error, sizeof(error));
                sprintf(error, "Replying to client failed.\n");
                perror(error);
                close(socketFD);
                exit(EXIT_FAILURE);
            }
        
        // Set the socket to listen for 5 seconds
        setsockopt(socketFD, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        bzero(buffer, sizeof(buffer));
        messageLength = recvfrom(socketFD, buffer, sizeof(buffer), 0, (struct sockaddr*)&clientAddress, &clientLength);
        buffer[messageLength] = '\0';

        // Handle the packet loss of chat_START_SSL_NOT_SUPPORTED_ACK acknowledgement
        if(messageLength > 0 && strcmp(buffer, "chat_START_SSL_NOT_SUPPORTED") == 0)
            goto chat_START_SSL_NOT_SUPPORTED_ACK;
        
        // Invoke the function to chat over UDP socket
        chatSocket(socketFD, clientAddress);

        // Close the socket and return
        close(socketFD);
        return;
    }

    // Handle the SSL_SUPPORTED case
    chat_START_SSL_ACK:
        
        // Send the chat_START_SSL_ACK control message
        bzero(buffer, sizeof(buffer));
        sprintf(buffer, "chat_START_SSL_ACK");
        if(sendto(socketFD, buffer, sizeof(buffer), 0, (struct sockaddr*)&clientAddress, clientLength) == -1) {
            bzero(error, sizeof(error));
            sprintf(error, "Replying to client failed.\n");
            perror(error);
            close(socketFD);
            exit(EXIT_FAILURE);
        }
    
    // Set the socket to listen for 5 seconds
    setsockopt(socketFD, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    bzero(buffer, sizeof(buffer));
	messageLength = recvfrom(socketFD, buffer, sizeof(buffer), 0, (struct sockaddr*)&clientAddress, &clientLength);
    buffer[messageLength] = '\0';

    // Handle the packet loss of chat_START_SSL_ACK acknowledgement
	if(messageLength > 0 && strcmp(buffer, "chat_START_SSL") == 0)
	    goto chat_START_SSL_ACK;

    // Load the SSL Library components
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    // Setup a new SSL context and handle the error
    SSL_CTX *context = SSL_CTX_new(DTLS_server_method());
    if(!context) {
        bzero(error, sizeof(error));
        sprintf(error, "SSL Context creation failed.\n");
        perror(error);
        close(socketFD);
        exit(EXIT_FAILURE);
    }
    
    // Configure the appropriate context options
    SSL_CTX_set_session_cache_mode(context, SSL_SESS_CACHE_SERVER);
    SSL_CTX_set_verify(context, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_cookie_generate_cb(context, generateCookie);
    SSL_CTX_set_cookie_verify_cb(context, &verifyCookie);
    
    // Set the security level to 1 and load the private key password
    SSL_CTX_set_security_level(context, 1);
    SSL_CTX_set_default_passwd_cb_userdata(context, host);

    // Load the server certificate
    if(SSL_CTX_use_certificate_file(context, "certificate.crt", SSL_FILETYPE_PEM) <= 0) {
        bzero(error, sizeof(error));
        sprintf(error, "Certificate loading failed.\n");
        perror(error);
        SSL_CTX_free(context);
        close(socketFD);
        exit(EXIT_FAILURE);
    }

    // Load the server private key
    if(SSL_CTX_use_PrivateKey_file(context, "private.pem", SSL_FILETYPE_PEM) <= 0 ) {
        bzero(error, sizeof(error));
        sprintf(error, "Private Key loading failed.\n");
        perror(error);
        SSL_CTX_free(context);
        close(socketFD);
        exit(EXIT_FAILURE);
    }

    // Check for the validity of private key and certificate
    if(!SSL_CTX_check_private_key(context)) {
        bzero(error, sizeof(error));
        sprintf(error, "Keys and Certificates do not match.\n");
        perror(error);
        SSL_CTX_free(context);
        close(socketFD);
        exit(EXIT_FAILURE);
    }

    // Load the CA certificate store
    SSL_CTX_load_verify_locations(context, "CAfile.crt", NULL);
    
    // Set up the Bio and SSL connection and handle the error
    BIO *bio = BIO_new_dgram(socketFD, BIO_NOCLOSE);
    SSL *connection = SSL_new(context);
    if(!connection){
        bzero(error, sizeof(error));
        sprintf(error, "SSL Connection creation failed\n");
        perror(error);
        BIO_free(bio);
        SSL_CTX_free(context);
        close(socketFD);
        exit(EXIT_FAILURE);
    }

    // Set the appropriate options for the connection and attach the connection to the bio
    SSL_set_ciphersuites(connection, "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305");
    SSL_set_bio(connection, bio, bio);
    SSL_set_options(connection, SSL_OP_COOKIE_EXCHANGE);

    // Set the socket to NON-BLOCKING mode
    flag = fcntl(socketFD, F_GETFL, 0);
    fcntl(socketFD, F_SETFL, flag | O_NONBLOCK);
    
    // Start listening to the BIO for SSL connections    
    do {
        status = DTLSv1_listen(connection, (BIO_ADDR*)&clientAddress);
    }while(status <= 0);

    // Accept the SSL connection
    do {
        status = SSL_accept(connection);
    }while(status <= 0);

    // Verify the Peer Certificate and handle the error
    if(!SSL_get_peer_certificate(connection) || !SSL_get_verify_result(connection) == X509_V_OK) {
        bzero(error, sizeof(error));
        sprintf(error, "Peer Certificate verification failed.\n");
        perror(error);
        SSL_shutdown(connection);
        SSL_free(connection);
        BIO_free(bio);
        SSL_CTX_free(context);
        close(socketFD);
        exit(EXIT_FAILURE);
    }

    // Invoke the function to chat over SSL socket
    chatSSL(connection);

    // Free the resources and return
    SSL_shutdown(connection);
    SSL_free(connection);
    SSL_CTX_free(context);
    close(socketFD);
    return;
}

/**
Name        :   asClient()
Description :   Defines the procedure for connection setup on the client side before the chat.
Arguments   :   Hostname of the server to be connected with
Return      :   None
**/
void asClient(char *server) {
    
    // Declare the required local variables
    char buffer[MAX_LENGTH], ip[20];
    int socketFD, serverLength, messageLength, status, flag;
    struct sockaddr_in serverAddress;
    const unsigned char cookie[SECRET_LENGTH], *ticket;
    struct timeval timeout = {2, 0};
    unsigned int length;
    
    // Try creating a Client Socket and print appropriate message
    bzero(&serverAddress, sizeof(serverAddress));
    if((socketFD = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        bzero(error, sizeof(error));
        sprintf(error, "Socket creation failed.\n");
        perror(error);
        exit(EXIT_FAILURE);
    }

    // Prepare the server address details for connection
    retrieveIP(server, ip);
    serverAddress.sin_addr.s_addr = inet_addr(ip);
    serverAddress.sin_port = htons(PORT);
    serverAddress.sin_family = AF_INET;
    setsockopt(socketFD, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    serverLength = sizeof(serverAddress);

    // Try connecting to the server
    if(connect(socketFD, (struct sockaddr*)&serverAddress, serverLength)) {
        bzero(error, sizeof(error));
        sprintf(error, "Server connection failed.\n");
        perror(error);
        close(socketFD);
        exit(EXIT_FAILURE);
    }

    // Send chat_hello to the server
    chat_hello:
        bzero(buffer, sizeof(buffer));
        sprintf(buffer, "chat_hello");
        if(sendto(socketFD, buffer, sizeof(buffer), 0, (struct sockaddr*)&serverAddress, serverLength) < 0) {
            bzero(error, sizeof(error));
            sprintf(error, "Message sending failed.\n");
            perror(error);
            close(socketFD);
            exit(EXIT_FAILURE);
        }

    // Try to receive chat_ok_reply from the server and handle packet loss of chat_hello
    bzero(buffer, sizeof(buffer));
    if(recvfrom(socketFD, buffer, sizeof(buffer), 0, (struct sockaddr*)&serverAddress, &serverLength) < 0)
        goto chat_hello;

    // Send chat_START_SSL to the server
    chat_START_SSL:
        bzero(buffer, sizeof(buffer));
        sprintf(buffer, "chat_START_SSL");
        if(sendto(socketFD, buffer, sizeof(buffer), 0, (struct sockaddr*)&serverAddress, serverLength) < 0) {
            bzero(error, sizeof(error));
            sprintf(error, "Message sending failed.\n");
            perror(error);
            close(socketFD);
            exit(EXIT_FAILURE);
        }
        printf("Sent chat_START_SSL\n");
    
    // Try to receive a reply from the server and handle packet loss of chat_START_SSL
    bzero(buffer, sizeof(buffer));
    if(recvfrom(socketFD, buffer, sizeof(buffer), 0, (struct sockaddr*)&serverAddress, &serverLength) < 0)
        goto chat_START_SSL;

    // Handle the SSL_NOT_SUPPORTED case
    if(strcmp(buffer, "chat_START_SSL_NOT_SUPPORTED") == 0) {
        
        // Invoke the function to chat over the UDP socket
        chatSocket(socketFD, serverAddress);

        // Close the socket and return
        close(socketFD);
        return;
    }

    // Handle the SSL_SUPPORTED CASE
    if(strcmp(buffer, "chat_START_SSL_ACK")) {
        bzero(error, sizeof(error));
        sprintf(error, "Invalid Message received\n");
        perror(error);
        close(socketFD);
        exit(EXIT_FAILURE);
    }
    
    // Wait for 5 seconds to synchronize with the server
    sleep(5);

    // Load the SSL Library components
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    // Setup a new SSL context and handle the error
    SSL_CTX *context = SSL_CTX_new(DTLS_client_method());
    if(!context) {
        bzero(error, sizeof(error));
        sprintf(error, "SSL Context creation failed.\n");
        perror(error);
        close(socketFD);
        exit(EXIT_FAILURE);
    }

    // Set the appropriate options for the SSL context
    SSL_CTX_set_verify(context, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    SSL_CTX_set_verify_depth(context, 2);
    
    // Set the security level to 1 and load the private key password
    SSL_CTX_set_default_passwd_cb_userdata(context, host);
    SSL_CTX_set_security_level(context, 1);

    // Load the client certificate
    if(SSL_CTX_use_certificate_file(context, "certificate.crt", SSL_FILETYPE_PEM) < 0) {
        bzero(error, sizeof(error));
        sprintf(error, "Certificate loading failed.\n");
        perror(error);
        SSL_CTX_free(context);
        close(socketFD);
        exit(EXIT_FAILURE);
    }

    // Load the client private key
    if(SSL_CTX_use_PrivateKey_file(context, "private.pem", SSL_FILETYPE_PEM) <= 0 ) {
        bzero(error, sizeof(error));
        sprintf(error, "Keys loading failed.\n");
        perror(error);
        SSL_CTX_free(context);
        close(socketFD);
        exit(EXIT_FAILURE);
    }

    // Check for the validity of private key and certificate
    if(!SSL_CTX_check_private_key(context)) {
        bzero(error, sizeof(error));
        sprintf(error, "Keys and Certificates do not match.\n");
        perror(error);
        SSL_CTX_free(context);
        close(socketFD);
        exit(EXIT_FAILURE);
    }

    // Load the CA certificate store
    SSL_CTX_load_verify_locations(context, "CAfile.crt", NULL);

    // Create a new SSL connection and handle the error
    SSL *connection = SSL_new(context);
    if(!connection) {
        bzero(error, sizeof(error));
        sprintf(error, "SSL Connection creation failed.\n");
        perror(error);
        SSL_CTX_free(context);
        close(socketFD);
        exit(EXIT_FAILURE);
    }

    // Set the appropriate options for the connection and bind it to the socket
    SSL_set_ciphersuites(connection, "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305");
    if(SSL_set_fd(connection, socketFD) != 1) {
        bzero(error, sizeof(error));
        sprintf(error, "Socket setting failed.\n");
        perror(error);
        SSL_shutdown(connection);
        SSL_free(connection);
        SSL_CTX_free(context);
        close(socketFD);
        exit(EXIT_FAILURE);
    }

    // Set the socket to NON-BLOCKING mode
    flag = fcntl(socketFD, F_GETFL, 0);
    fcntl(socketFD, F_SETFL, flag | O_NONBLOCK);
    
    // Try establishing SSL connection with the server
    do {
        status = SSL_connect(connection);
    }while(status != 1);

    // Verify the peer certificate
    if(!SSL_get_peer_certificate(connection) || !SSL_get_verify_result(connection) == X509_V_OK) {
        bzero(error, sizeof(error));
        sprintf(error, "SSL Connection failed.\n");
        perror(error);
        SSL_shutdown(connection);
        SSL_free(connection);
        SSL_CTX_free(context);
        close(socketFD);
        exit(EXIT_FAILURE);
    }

    // Invoke the function to chat over the SSL socket
    chatSSL(connection);

    // Free the resources and return
    SSL_shutdown(connection);
    SSL_free(connection);
    SSL_CTX_free(context);
    close(socketFD);
    return;
}

/**
Name        :   main()
Description :   Handles the invoking of all above defined functions.
Arguments   :   Role of the peer and server to be connected with (in case of client)
Return      :   Integer 0 on success and EXIT_FAILURE otherwise
**/
int main(int argc, char **argv) {

    // Retrieve the host name
    if (gethostname(host, sizeof(host)) == -1) {
        bzero(error, sizeof(error));
        sprintf(error, "gethostname error");
        perror(error);
        exit(EXIT_FAILURE);
    }

    // Parse and validate the command line arguments to invoke the appropriate function
    if(argc == 2 && strcmp(argv[1], "-s") == 0)
        asServer();
    else if(argc == 3 && strcmp(argv[1], "-c") == 0)
        asClient(argv[2]);
    else {
        bzero(error, sizeof(error));
        sprintf(error, "Invalid Command Line Arguments. Refer README.md\n");
        perror(error);
        exit(EXIT_FAILURE);
    }

    return 0;
}