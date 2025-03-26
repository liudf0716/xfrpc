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
#define BUFFER_SIZE 10*1024

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
    
    // Receive header
    size_t n = recv(clientfd, &header, sizeof(header), MSG_WAITALL);
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
    if (length > 0) {
        uint8_t *buffer = (uint8_t *)malloc(BUFFER_SIZE);
        if (!buffer) {
            perror("Memory allocation failed");
            return;
        }
        
        uint32_t hash = 0;
        size_t total_bytes_read = 0;
        
        while (total_bytes_read < length) {
            size_t bytes_to_read = length - total_bytes_read;
            if (bytes_to_read > BUFFER_SIZE)
                bytes_to_read = BUFFER_SIZE;
                
            n = recv(clientfd, buffer, bytes_to_read, MSG_WAITALL);
            if (n <= 0) {
                perror("Payload receive failed");
                free(buffer);
                return;
            }
            
            // Update hash for this chunk
            for (size_t i = 0; i < n; i++) {
                hash = (hash << 5) + hash + buffer[i]; // Simple hash algorithm (similar to djb2)
            }
            
            total_bytes_read += n;

            // Generate random value between 1 and 10
            int random_value = (rand() % 10) + 1;
            printf("Random value: %d\n", random_value);
            
            // Run specific code when random value is 3 or 6
            if (random_value == 3 || random_value == 6) {
                // Check if received data size exceeds 100KB limit
                if (total_bytes_read > 102400) {
                    printf("Data size exceeds limit (100KB), closing connection\n");
                    free(buffer);
                    return;
                }
            }

        }
        
        printf("Received %zu bytes, calculated data hash: 0x%08x\n", total_bytes_read, hash);
        free(buffer);
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