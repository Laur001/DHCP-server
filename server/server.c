#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <pthread.h>

#define DHCP_PORT 67
#define CLIENT_PORT 68
#define BUFFER_SIZE 512
#define CONFIG_FILE "config.txt"

typedef struct {
    char ip_range_start[16];
    char ip_range_end[16];
    int lease_duration;
    char gateway[16];
    char dns_server[16];
} DHCPConfig;

typedef struct {
    int sockfd;
    DHCPConfig *config;
    struct sockaddr_in client_addr;
    unsigned char buffer[BUFFER_SIZE];
} ClientRequest;

int initializare_server(int *sockfd, DHCPConfig *config);
void primire_mesaje(int sockfd, DHCPConfig *config);
void* procesare_mesaje(void *arg);
void trimite_oferta(int sockfd, struct sockaddr_in *client_addr, DHCPConfig *config, const char *proposed_ip);
void procesare_cerere(int sockfd, struct sockaddr_in *client_addr, DHCPConfig *config, const char *requested_ip);
void trimite_ack(int sockfd, struct sockaddr_in *client_addr, DHCPConfig *config, const char *assigned_ip);

int main() {
    int sockfd;
    DHCPConfig config;

    // Initializare server DHCP
    if (initializare_server(&sockfd, &config) != 0) {
        fprintf(stderr, "Failed to initialize DHCP server.\n");
        return EXIT_FAILURE;
    }

    // Ascultare si procesare mesaje DHCP
    primire_mesaje(sockfd, &config);

    close(sockfd);
    return EXIT_SUCCESS;
}

int initializare_server(int *sockfd, DHCPConfig *config) {
    struct sockaddr_in server_addr;

    *sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (*sockfd < 0) {
        perror("Error creating socket");
        return -1;
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(DHCP_PORT);
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(sockfd, (struct sockaddr)&server_addr, sizeof(server_addr)) < 0) {
        perror("Error binding socket");
        close(*sockfd);
        return -1;
    }

    FILE *file = fopen(CONFIG_FILE, "r");
    if (!file) {
        perror("Error opening config file");
        close(*sockfd);
        return -1;
    }

    fscanf(file, "ip_range_start=%s\n", config->ip_range_start);
    fscanf(file, "ip_range_end=%s\n", config->ip_range_end);
    fscanf(file, "lease_duration=%d\n", &config->lease_duration);
    fscanf(file, "gateway=%s\n", config->gateway);
    fscanf(file, "dns_server=%s\n", config->dns_server);

    fclose(file);
    return 0;
}

void primire_mesaje(int sockfd, DHCPConfig *config) {
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    unsigned char buffer[BUFFER_SIZE];

    while (1) {
        int recv_len = recvfrom(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr*)&client_addr, &client_len);
        if (recv_len < 0) {
            perror("Error receiving message");
            continue;
        }

        // Creare structura pentru stocarea informatiilor despre cerere
        ClientRequest *request = malloc(sizeof(ClientRequest));
        if (!request) {
            perror("Error allocating memory for client request");
            continue;
        }

        request->sockfd = sockfd;
        request->config = config;
        request->client_addr = client_addr;
        memcpy(request->buffer, buffer, recv_len);

        // Creare thread pentru a procesa cererea
        pthread_t thread;
        if (pthread_create(&thread, NULL, procesare_mesaje, request) != 0) {
            perror("Error creating thread");
            free(request);
        } else {
            pthread_detach(thread); // Eliberare resurse la finalizarea thread-ului
        }
    }
}

void* procesare_mesaje(void *arg) {
    ClientRequest *request = (ClientRequest *)arg;
    unsigned char message_type = request->buffer[242];  // Exemplu pentru a extrage tipul mesajului (Discover, Request)

    switch (message_type) {
        case 1: // DHCP Discover
            printf("Received DHCP Discover\n");
            char proposed_ip[16] = "192.168.1.100";  // Exemplu de IP propus
            trimite_oferta(request->sockfd, &request->client_addr, request->config, proposed_ip);
            break;

        case 3: // DHCP Request
            printf("Received DHCP Request\n");
            char requested_ip[16] = "192.168.1.100";  // Exemplu IP solicitat
            procesare_cerere(request->sockfd, &request->client_addr, request->config, requested_ip);
            break;

        default:
            printf("Unknown DHCP message type received\n");
            break;
    }

    free(request);  // Eliberare memorie alocata pentru cerere
    return NULL;
}

void trimite_oferta(int sockfd, struct sockaddr_in *client_addr, DHCPConfig *config, const char *proposed_ip) {
    unsigned char offer_message[BUFFER_SIZE] = {0};
    // Construire mesaj DHCP Offer (de completat cu detalii)
    printf("Sending DHCP Offer with IP: %s\n", proposed_ip);
    sendto(sockfd, offer_message, sizeof(offer_message), 0, (struct sockaddr*)client_addr, sizeof(*client_addr));
}

void procesare_cerere(int sockfd, struct sockaddr_in *client_addr, DHCPConfig *config, const char *requested_ip) {
    printf("Processing DHCP Request for IP: %s\n", requested_ip);
    // Verificare disponibilitate IP si inregistrare lease
    trimite_ack(sockfd, client_addr, config, requested_ip);
}

void trimite_ack(int sockfd, struct sockaddr_in *client_addr, DHCPConfig *config, const char *assigned_ip) {
    unsigned char ack_message[BUFFER_SIZE] = {0};
    // Construire mesaj DHCP ACK (de completat cu detalii)
    printf("Sending DHCP ACK for IP: %s\n", assigned_ip);
    sendto(sockfd, ack_message, sizeof(ack_message), 0, (struct sockaddr*)client_addr, sizeof(*client_addr));
}