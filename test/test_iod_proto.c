#ifndef TEST_IOD_PROTO_H
#define TEST_IOD_PROTO_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netinet/in.h>
#include <time.h>
#include <stdbool.h>
#include <errno.h>

#define IOD_MAGIC 0xEFEFB0B0

struct iod_header {
    uint32_t magic;
    uint32_t type;
    uint64_t unique_id;
    uint32_t vip4;
    uint32_t length;
    uint8_t data[0];
};


typedef struct {
    int sockfd;
    struct sockaddr_in serverAddr;
    bool isConnected;
} IODClient;

// Initialize the client
void initIODClient(IODClient* client) {
    client->sockfd = -1;
    client->isConnected = false;
}

// Connect to server
bool connectIODClient(IODClient* client, const char* serverIp, int port) {
    // Create socket
    client->sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (client->sockfd < 0) {
        fprintf(stderr, "Error creating socket\n");
        return false;
    }
    
    // Set up server address
    memset(&client->serverAddr, 0, sizeof(client->serverAddr));
    client->serverAddr.sin_family = AF_INET;
    client->serverAddr.sin_port = htons(port);
    
    if (inet_pton(AF_INET, serverIp, &client->serverAddr.sin_addr) <= 0) {
        fprintf(stderr, "Invalid address/Address not supported\n");
        close(client->sockfd);
        client->sockfd = -1;
        return false;
    }
    
    // Connect to the server
    if (connect(client->sockfd, (struct sockaddr*)&client->serverAddr, sizeof(client->serverAddr)) < 0) {
        fprintf(stderr, "Connection failed\n");
        close(client->sockfd);
        client->sockfd = -1;
        return false;
    }
    
    client->isConnected = true;
    return true;
}

// Send a packet
bool sendIODPacket(IODClient* client, const struct iod_header* header, uint32_t length) {
    if (!client->isConnected) {
        fprintf(stderr, "Not connected to server\n");
        return false;
    }
    uint32_t nsend = send(client->sockfd, header, length, 0);
    if (nsend != length) {
        fprintf(stderr, "Failed to send packet [%d] : %s\n", nsend, strerror(errno));
        return false;
    }
    
    return true;
}

// Receive response
bool receiveIODResponse(IODClient* client, struct iod_header* header, char* payload, size_t maxPayloadSize) {
    if (!client->isConnected) {
        fprintf(stderr, "Not connected to server\n");
        return false;
    }
    
    // Receive header
    ssize_t bytesRead = recv(client->sockfd, header, sizeof(struct iod_header), 0);
    if (bytesRead != sizeof(struct iod_header)) {
        fprintf(stderr, "Failed to receive header\n");
        return false;
    }
    
    fprintf(stderr, "Received header: magic=%u, type=%u, unique_id=%lu, vip4=%u, length=%u\n",
            ntohl(header->magic), ntohl(header->type), header->unique_id, ntohl(header->vip4), ntohl(header->length));

    // Receive payload if present
    header->length = ntohl(header->length);
    if (header->length > 0) {
        if (header->length > maxPayloadSize) {
            fprintf(stderr, "Payload too large for buffer\n");
            return false;
        }
        
        bytesRead = recv(client->sockfd, payload, header->length, 0);
        if (bytesRead != header->length) {
            fprintf(stderr, "Failed to receive payload\n");
            return false;
        }
    }
    
    return true;
}

// Disconnect
void disconnectIODClient(IODClient* client) {
    if (client->sockfd != -1) {
        close(client->sockfd);
        client->sockfd = -1;
        client->isConnected = false;
    }
}

// Example usage:
int main() {
    char serverIp[64];
    char vip4[64];  
    int port;
    int type;
    
    // Set default values
    strcpy(serverIp, "192.168.10.185");
    port = 6431;
    strcpy(vip4, "192.168.10.181");
    type = 100000;
    
    char choice;
    printf("Use default values? (y/n): ");
    scanf(" %c", &choice);
    
    if (choice != 'y' && choice != 'Y') {
        printf("Enter server IP [%s]: ", serverIp);
        char input[64];
        if (scanf("%63s", input) == 1 && input[0] != '\0')
            strcpy(serverIp, input);
            
        printf("Enter port [%d]: ", port);
        if (scanf("%d", &port) != 1)
            port = 6431; // Reset to default if invalid input
            
        printf("Enter vip4 [%s]: ", vip4);
        if (scanf("%63s", input) == 1 && input[0] != '\0')
            strcpy(vip4, input);
            
        printf("Enter type [%d]: ", type);
        if (scanf("%d", &type) != 1)
            type = 100000; // Reset to default if invalid input
    }
    
    printf("Using: Server=%s, Port=%d, VIP4=%s, Type=%d\n", 
           serverIp, port, vip4, type);
    
    // convert x.x.x.x to network byte order
    uint32_t vip4_nbo = inet_addr(vip4);

    IODClient client;
    initIODClient(&client);
    
    if (connectIODClient(&client, serverIp, port)) {
        printf("Connected to server\n");
        
        // Prepare random data to send
        const char *message = "Hello IOD Server!";
        size_t messageLen = strlen(message) + 1;  // +1 for null terminator
        
        // Set up the header according to our struct definition
        struct iod_header *header = (struct iod_header *)malloc(sizeof(struct iod_header) + messageLen);
        if (!header) {
            fprintf(stderr, "Failed to allocate memory for header\n");
            disconnectIODClient(&client);
            return 1;
        }
        header->magic = htonl(IOD_MAGIC);  // Using the defined magic number
        header->type = htonl(type);
        header->unique_id = (uint64_t)time(NULL);  // Use timestamp as unique ID
        header->vip4 = vip4_nbo;
        header->length = htonl(messageLen);
        memcpy(header->data, message, messageLen);
        
        if (sendIODPacket(&client, header, sizeof(struct iod_header) + messageLen)) {
            printf("Packet sent successfully with message: %s\n", message);
            
            // Prepare for response
            struct iod_header responseHeader;
            char responseBuffer[1024] = {0};
            
            if (receiveIODResponse(&client, &responseHeader, responseBuffer, sizeof(responseBuffer))) {
                printf("Received response (type: %u, length: %u)\n", 
                       responseHeader.type, responseHeader.length);
                
                if (responseHeader.length > 0) {
                    printf("Response data: %s\n", responseBuffer);
                }
            }
        }
        
        disconnectIODClient(&client);
    }
    
    return 0;
}

#endif // TEST_IOD_PROTO_H