#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <errno.h>
#include <stdbool.h>
#include "iod_proto.h"

#define MAX_CLIENTS 10
#define BUFFER_SIZE 1024*1024

typedef struct {
    int sockfd;
    struct sockaddr_in serverAddr;
    bool isRunning;
} IODServer;

// Initialize server
static bool initIODServer(IODServer* server, int port) {
    server->sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (server->sockfd < 0) {
        perror("Socket creation failed");
        return false;
    }

    int opt = 1;
    if (setsockopt(server->sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt failed");
        close(server->sockfd);
        return false;
    }

    memset(&server->serverAddr, 0, sizeof(server->serverAddr));
    server->serverAddr.sin_family = AF_INET;
    server->serverAddr.sin_addr.s_addr = INADDR_ANY;
    server->serverAddr.sin_port = htons(port);

    if (bind(server->sockfd, (struct sockaddr*)&server->serverAddr, sizeof(server->serverAddr)) < 0) {
        perror("Bind failed");
        close(server->sockfd);
        return false;
    }

    if (listen(server->sockfd, MAX_CLIENTS) < 0) {
        perror("Listen failed");
        close(server->sockfd);
        return false;
    }

    server->isRunning = true;
    return true;
}

static void handleClient(int clientfd) {
    struct iod_header header;
    uint8_t buffer[BUFFER_SIZE] = {0};
    
    // Receive header
    ssize_t n = recv(clientfd, &header, sizeof(header), MSG_WAITALL);
    if (n != sizeof(header)) {
        perror("Header receive failed");
        return;
    }

    // Validate header
    if (!is_valid_iod_header(&header)) {
        printf("Invalid IOD header received\n");
        return;
    }

    // Handle payload if present
    uint32_t length = ntohl(header.length);
    printf("Received header: type=%u, unique_id=%lu, vip4=%u, length=%u\n", 
           ntohl(header.type), header.unique_id, ntohl(header.vip4), length);
    if (length > 0 && length < BUFFER_SIZE) {
        n = recv(clientfd, buffer, length, MSG_WAITALL);
        if (n != length) {
            perror("Payload receive failed");
            return;
        }
        
        uint32_t hash = 0;
        if (length > 0) {
            printf("received data is %s\n", buffer);
            for (uint32_t i = 0; i < length; i++) {
            hash = (hash << 5) + hash + buffer[i]; // A simple hash algorithm (similar to djb2)
            }
            printf("Calculated data hash: 0x%08x\n", hash);
        }
    }

    // Prepare and send response
    header.type = htonl(ntohl(header.type) | 0x100); // Convert to ACK type
    header.length = 0;
    
    if (send(clientfd, &header, sizeof(header), 0) != sizeof(header)) {
        perror("Response send failed");
    }
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <port>\n", argv[0]);
        return 1;
    }

    IODServer server;
    int port = atoi(argv[1]);

    if (!initIODServer(&server, port)) {
        printf("Failed to initialize server\n");
        return 1;
    }

    printf("IOD Server listening on port %d...\n", port);

    while (server.isRunning) {
        struct sockaddr_in clientAddr;
        socklen_t clientLen = sizeof(clientAddr);
        
        int clientfd = accept(server.sockfd, (struct sockaddr*)&clientAddr, &clientLen);
        if (clientfd < 0) {
            perror("Accept failed");
            continue;
        }

        printf("New connection from %s:%d\n", 
               inet_ntoa(clientAddr.sin_addr), 
               ntohs(clientAddr.sin_port));

        handleClient(clientfd);
        close(clientfd);
    }

    close(server.sockfd);
    return 0;
}