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
#include <ctype.h>
#include <pthread.h>

#define IOD_MAGIC 0xEFEFB0B0
#define MAX_PAYLOAD_SIZE 4096

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

typedef struct {
    char serverIp[64];
    int port;
    uint32_t vip4_nbo;
    int type;
    int min_data_len;
    int max_data_len;
    int thread_id;
} ThreadArgs;

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

// Generate random data length between min and max
int getRandomDataLength(int min, int max) {
    return min + rand() % (max - min + 1);
}

// Thread function for sending packets
void* sendPacketsThread(void* arg) {
    ThreadArgs* args = (ThreadArgs*)arg;
    IODClient client;
    
    initIODClient(&client);
    
    if (connectIODClient(&client, args->serverIp, args->port)) {
        printf("Thread %d: Connected to server\n", args->thread_id);
        
        // Generate random data length
        int dlen = getRandomDataLength(args->min_data_len, args->max_data_len);
        
        // Set up the header
        struct iod_header *header = (struct iod_header *)malloc(sizeof(struct iod_header) + dlen);
        if (!header) {
            fprintf(stderr, "Thread %d: Failed to allocate memory for header\n", args->thread_id);
            disconnectIODClient(&client);
            pthread_exit(NULL);
        }
        
        memset(header, 0, sizeof(struct iod_header) + dlen);
        
        header->magic = htonl(IOD_MAGIC);
        header->type = htonl(args->type);
        header->unique_id = (uint64_t)time(NULL) + args->thread_id;  // Make unique ID per thread
        header->vip4 = args->vip4_nbo;
        header->length = htonl(dlen);
        
        // Fill data with random content
        for (int i = 0; i < dlen; i++) {
            header->data[i] = 'A' + (i % 26); 
        }


        printf("Thread %d: Sending packet with data length %d\n", args->thread_id, dlen);
        
        // Generate random value between 1 and 10
        int random_value = 1 + (rand() % 10);
        printf("Thread %d: Generated random value: %d\n", args->thread_id, random_value);
        
        // Only execute the following code if random_value is 4, 5, 6, 7 or 8
        if (random_value >= 4 && random_value <= 8) {
            // firstly send only header to server
            if (sendIODPacket(&client, header, sizeof(struct iod_header))) {
            printf("Thread %d: Header sent successfully\n", args->thread_id);
            struct iod_header responseHeader;
            char responseBuffer[MAX_PAYLOAD_SIZE] = {0};

            if (receiveIODResponse(&client, &responseHeader, responseBuffer, sizeof(responseBuffer))) {
                printf("Thread %d: Received header response (type: %u, length: %u)\n", 
                   args->thread_id, responseHeader.type, responseHeader.length);
            }
            }
        }
    
        printf("Thread %d: Sending whole data\n", args->thread_id);
        if (sendIODPacket(&client, header, sizeof(struct iod_header) + dlen)) {
            printf("Thread %d: Whole data sent successfully\n", args->thread_id);
            
            // Prepare for response
            struct iod_header responseHeader;
            char responseBuffer[MAX_PAYLOAD_SIZE] = {0};
            
            if (receiveIODResponse(&client, &responseHeader, responseBuffer, sizeof(responseBuffer))) {
                printf("Thread %d: Received response (type: %u, length: %u)\n", 
                       args->thread_id, responseHeader.type, responseHeader.length);
                
                if (responseHeader.length > 0) {
                    printf("Thread %d: Response data: %.*s\n", args->thread_id, 
                           responseHeader.length > 50 ? 50 : responseHeader.length, responseBuffer);
                }
            }
        }
        
        free(header);
        disconnectIODClient(&client);
    } else {
        printf("Thread %d: Failed to connect to server\n", args->thread_id);
    }
    
    pthread_exit(NULL);
}

// Load configuration from file
void loadConfiguration(char* serverIp, int* port, char* vip4, int* type) {
    // Default values
    strcpy(serverIp, "192.168.10.185");
    *port = 12321;
    strcpy(vip4, "1.2.3.33");
    *type = 100000;
    
    FILE *config_file = fopen("iod.conf", "r");
    if (config_file == NULL) {
        printf("Could not open configuration file (iod.conf). Using defaults.\n");
        return;
    }
    
    char line[256];
    char key[64], value[192];
    
    while (fgets(line, sizeof(line), config_file)) {
        // Skip comments and empty lines
        if (line[0] == '#' || line[0] == '\n') continue;
        
        if (sscanf(line, "%63[^=]=%191s", key, value) == 2) {
            // Remove trailing whitespaces from key
            char *ptr = key + strlen(key) - 1;
            while (ptr >= key && isspace((unsigned char)*ptr)) {
                *ptr = '\0';
                ptr--;
            }
            
            if (strcmp(key, "server_ip") == 0) {
                strcpy(serverIp, value);
            } else if (strcmp(key, "port") == 0) {
                *port = atoi(value);
            } else if (strcmp(key, "vip4") == 0) {
                strcpy(vip4, value);
            } else if (strcmp(key, "type") == 0) {
                *type = atoi(value);
            }
        }
    }
    
    fclose(config_file);
    printf("Configuration loaded from iod.conf\n");
}

// Main function
int main() {
    char serverIp[64];
    char vip4[64];  
    int port;
    int type;
    int min_data_len, max_data_len;
    int num_threads;
    
    // Load configuration
    loadConfiguration(serverIp, &port, vip4, &type);
    
    // Get user input for threads and data length range
    printf("Enter minimum data length: ");
    if (scanf("%d", &min_data_len) != 1 || min_data_len < 0)
        min_data_len = 0;
    
    printf("Enter maximum data length: ");
    if (scanf("%d", &max_data_len) != 1 || max_data_len < min_data_len)
        max_data_len = min_data_len + 100;
    
    printf("Enter number of threads: ");
    if (scanf("%d", &num_threads) != 1 || num_threads < 1)
        num_threads = 1;
        
    printf("Using: Server=%s, Port=%d, VIP4=%s, Type=%d, Threads=%d, Data Length Range=%d-%d\n", 
           serverIp, port, vip4, type, num_threads, min_data_len, max_data_len);
    
    // Initialize random seed
    srand(time(NULL));
    
    // Convert vip4 to network byte order
    uint32_t vip4_nbo = inet_addr(vip4);
    
    // Create threads
    pthread_t threads[num_threads];
    ThreadArgs thread_args[num_threads];
    
    for (int i = 0; i < num_threads; i++) {
        strcpy(thread_args[i].serverIp, serverIp);
        thread_args[i].port = port;
        thread_args[i].vip4_nbo = vip4_nbo;
        thread_args[i].type = type;
        thread_args[i].min_data_len = min_data_len;
        thread_args[i].max_data_len = max_data_len;
        thread_args[i].thread_id = i + 1;
        
        if (pthread_create(&threads[i], NULL, sendPacketsThread, (void*)&thread_args[i]) != 0) {
            fprintf(stderr, "Failed to create thread %d\n", i + 1);
        }
    }
    
    // Wait for all threads to complete
    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }
    
    printf("All threads completed\n");
    
    return 0;
}

#endif // TEST_IOD_PROTO_H