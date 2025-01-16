#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <pthread.h>
#include <time.h>
#include <errno.h>
#include <stdarg.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <netdb.h>
#include <signal.h>


#define DHCP_SERVER_PORT 67
#define DHCP_CLIENT_PORT 68
#define BUFFER_SIZE 1024
#define CONFIG_FILE "config.txt"
#define MAX_LEASES 100
#define DHCP_MAGIC_COOKIE "\x63\x82\x53\x63"


#define DHCP_DISCOVER 1
#define DHCP_OFFER    2
#define DHCP_REQUEST  3
#define DHCP_DECLINE  4
#define DHCP_ACK      5
#define DHCP_NAK      6
#define DHCP_RELEASE  7


#define OPT_SUBNET_MASK     1
#define OPT_ROUTER          3
#define OPT_DNS_SERVER      6
#define OPT_REQUESTED_IP   50
#define OPT_LEASE_TIME     51
#define OPT_MSG_TYPE       53
#define OPT_SERVER_ID      54
#define OPT_END           255

typedef struct {
    char ip_range_start[16];
    char ip_range_end[16];
    int lease_duration;
    char gateway[16];
    char dns_server[16];
    char subnet_mask[16];
    char server_identifier[16];
} DHCPConfig;

typedef struct {
    char ip[16];
    int is_leased;  
    time_t lease_expiry;
    unsigned char mac[6];  
} IPTableEntry;

typedef struct {
    int sockfd;
    unsigned char *buffer;
    int len;
    struct sockaddr_in client_addr;
    DHCPConfig *config;
} ThreadArgs;


volatile sig_atomic_t keep_running = 1;


IPTableEntry ip_table[MAX_LEASES];
int ip_table_size = 0;
pthread_mutex_t lease_mutex = PTHREAD_MUTEX_INITIALIZER;


void set_server_identifier(DHCPConfig *config, const char *interface_name);
int initialize_server(int *sockfd, DHCPConfig *config);
void run_server(int sockfd, DHCPConfig *config);
void process_dhcp_message(int sockfd, unsigned char *buffer, int len,
                          struct sockaddr_in *client_addr, DHCPConfig *config);
void handle_discover(int sockfd, unsigned char *buffer, struct sockaddr_in *client_addr,
                     DHCPConfig *config);
void handle_request(int sockfd, unsigned char *buffer, struct sockaddr_in *client_addr,
                    DHCPConfig *config);
void send_dhcp_packet(int sockfd, struct sockaddr_in *client_addr, unsigned char msg_type,
                      unsigned char *request_buffer, const char *yiaddr, DHCPConfig *config);
void build_ip_table(DHCPConfig *config);
char *allocate_ip(DHCPConfig *config, unsigned char *mac);
int is_ip_available(const char *ip, const unsigned char *mac);
void add_dhcp_option(unsigned char *packet, int *offset, unsigned char option,
                     unsigned char length, const unsigned char *data);
void log_message(const char *format, ...);
void *clean_expired_leases(void *arg);
void start_cleaner_thread();
void handle_signal(int signal);
void *thread_handler(void *args_ptr);

int main(void) {
    signal(SIGTERM, handle_signal);  
    signal(SIGINT, handle_signal);   

    int sockfd;
    DHCPConfig config;

    if (initialize_server(&sockfd, &config) != 0) {
        fprintf(stderr, "Failed to initialize DHCP server.\n");
        return EXIT_FAILURE;
    }

    build_ip_table(&config);  
    start_cleaner_thread();   

    log_message("DHCP Server started successfully");

    while (keep_running) {
        run_server(sockfd, &config);  
    }

    log_message("DHCP Server shutting down.");
    close(sockfd);
    return EXIT_SUCCESS;
}

void *thread_handler(void *args_ptr) {
    ThreadArgs *args = (ThreadArgs *)args_ptr;

    
    process_dhcp_message(args->sockfd, args->buffer, args->len, &args->client_addr, args->config);

    
    free(args->buffer);
    free(args);

    return NULL;
}



void handle_signal(int signal) {
    if (signal == SIGTERM || signal == SIGINT) {
        keep_running = 0;  
        log_message("Received termination signal. Shutting down server...");
    }
}


void run_server(int sockfd, DHCPConfig *config) {
    while (keep_running) {
        unsigned char *buffer = malloc(BUFFER_SIZE);
        if (!buffer) {
            perror("Failed to allocate memory for buffer");
            continue;
        }
        memset(buffer, 0, BUFFER_SIZE);

        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);

        int received = recvfrom(sockfd, buffer, BUFFER_SIZE, 0,
                                (struct sockaddr *)&client_addr, &addr_len);

        if (received < 0) {
            perror("recvfrom failed");
            free(buffer);
            continue;
        }

        if (received < 240) {
            log_message("Received packet too small to be DHCP");
            free(buffer);
            continue;
        }

        
        ThreadArgs *args = malloc(sizeof(ThreadArgs));
        if (!args) {
            perror("Failed to allocate memory for thread arguments");
            free(buffer);
            continue;
        }
        args->sockfd = sockfd;
        args->buffer = buffer;
        args->len = received;
        args->client_addr = client_addr;
        args->config = config;

        
        pthread_t thread_id;
        if (pthread_create(&thread_id, NULL, thread_handler, args) != 0) {
            perror("Failed to create thread");
            free(buffer);
            free(args);
            continue;
        }
        
        pthread_detach(thread_id);
    }
}


void set_server_identifier(DHCPConfig *config, const char *interface_name) {
    struct ifaddrs *ifaddr, *ifa;
    int family, s;
    char host[NI_MAXHOST];

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        return;
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL)
            continue;

        family = ifa->ifa_addr->sa_family;

        if (family == AF_INET && strcmp(ifa->ifa_name, interface_name) == 0) {
            s = getnameinfo(ifa->ifa_addr,
                            sizeof(struct sockaddr_in),
                            host, NI_MAXHOST,
                            NULL, 0, NI_NUMERICHOST);
            if (s != 0) {
                fprintf(stderr, "getnameinfo() failed: %s\n", gai_strerror(s));
                continue;
            }

            strncpy(config->server_identifier, host, sizeof(config->server_identifier) - 1);
            config->server_identifier[sizeof(config->server_identifier) - 1] = '\0';
            break;
        }
    }

    freeifaddrs(ifaddr);
}

int initialize_server(int *sockfd, DHCPConfig *config) {
    struct sockaddr_in server_addr;
    int broadcast = 1;

    inet_pton(AF_INET, "192.168.1.2", &server_addr.sin_addr);

    *sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (*sockfd < 0) {
        perror("Socket creation failed");
        return -1;
    }

    if (setsockopt(*sockfd, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof(broadcast)) < 0) {
        perror("setsockopt SO_BROADCAST failed");
        close(*sockfd);
        return -1;
    }

    int reuse = 1;
    if (setsockopt(*sockfd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
        perror("setsockopt SO_REUSEADDR failed");
        close(*sockfd);
        return -1;
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(DHCP_SERVER_PORT);
    server_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(*sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        close(*sockfd);
        return -1;
    }

    FILE *file = fopen(CONFIG_FILE, "r");
    if (!file) {
        perror("Config file opening failed");
        close(*sockfd);
        return -1;
    }

    char line[256];
    while (fgets(line, sizeof(line), file)) {
        char key[32], value[32];
        if (sscanf(line, "%[^=]=%s", key, value) == 2) {
            if (strcmp(key, "ip_range_start") == 0) strcpy(config->ip_range_start, value);
            else if (strcmp(key, "ip_range_end") == 0) strcpy(config->ip_range_end, value);
            else if (strcmp(key, "lease_duration") == 0) config->lease_duration = atoi(value);
            else if (strcmp(key, "gateway") == 0) strcpy(config->gateway, value);
            else if (strcmp(key, "dns_server") == 0) strcpy(config->dns_server, value);
            else if (strcmp(key, "subnet_mask") == 0) strcpy(config->subnet_mask, value);
        }
    }
    fclose(file);

    set_server_identifier(config, "ens33");

    return 0;
}

void build_ip_table(DHCPConfig *config) {
    struct in_addr start_addr, end_addr, current_addr;
    inet_pton(AF_INET, config->ip_range_start, &start_addr);
    inet_pton(AF_INET, config->ip_range_end, &end_addr);

    uint32_t start_ip = ntohl(start_addr.s_addr);
    uint32_t end_ip = ntohl(end_addr.s_addr);

    pthread_mutex_lock(&lease_mutex);

    ip_table_size = 0;
    for (uint32_t ip = start_ip; ip <= end_ip && ip_table_size < MAX_LEASES; ip++) {
        current_addr.s_addr = htonl(ip);
        inet_ntop(AF_INET, &current_addr, ip_table[ip_table_size].ip, sizeof(ip_table[ip_table_size].ip));
        ip_table[ip_table_size].is_leased = 0;  
        ip_table[ip_table_size].lease_expiry = 0;  
        memset(ip_table[ip_table_size].mac, 0, sizeof(ip_table[ip_table_size].mac));  
        ip_table_size++;
    }

    pthread_mutex_unlock(&lease_mutex);

    log_message("IP table rebuilt with %d IPs in range %s - %s", ip_table_size,
                config->ip_range_start, config->ip_range_end);
}


char *allocate_ip(DHCPConfig *config, unsigned char *mac) {
    static char ip_buffer[16];
    time_t now = time(NULL);

    pthread_mutex_lock(&lease_mutex);

    for (int i = 0; i < ip_table_size; i++) {
        
        if (ip_table[i].is_leased && ip_table[i].lease_expiry < now) {
            ip_table[i].is_leased = 0;  
            memset(ip_table[i].mac, 0, sizeof(ip_table[i].mac));  
        }
    }

    
    for (int i = 0; i < ip_table_size; i++) {
        if (ip_table[i].is_leased && memcmp(ip_table[i].mac, mac, 6) == 0) {
            snprintf(ip_buffer, sizeof(ip_buffer), "%s", ip_table[i].ip);
            pthread_mutex_unlock(&lease_mutex);
            return ip_buffer;
        }
    }

    
    for (int i = 0; i < ip_table_size; i++) {
        if (!ip_table[i].is_leased) {
            ip_table[i].is_leased = 1;
            ip_table[i].lease_expiry = now + config->lease_duration;
            memcpy(ip_table[i].mac, mac, 6);  
            snprintf(ip_buffer, sizeof(ip_buffer), "%s", ip_table[i].ip);
            pthread_mutex_unlock(&lease_mutex);
            return ip_buffer;
        }
    }

    pthread_mutex_unlock(&lease_mutex);
    return NULL;  
}



int is_ip_available(const char *ip, const unsigned char *mac) {
    pthread_mutex_lock(&lease_mutex);

    for (int i = 0; i < ip_table_size; i++) {
        if (strcmp(ip_table[i].ip, ip) == 0) {
            
            if (ip_table[i].is_leased) {
                if (ip_table[i].lease_expiry < time(NULL)) {
                    ip_table[i].is_leased = 0;  
                    memset(ip_table[i].mac, 0, sizeof(ip_table[i].mac));  
                    pthread_mutex_unlock(&lease_mutex);
                    return 1;  
                }
                
                if (memcmp(ip_table[i].mac, mac, 6) == 0) {
                    pthread_mutex_unlock(&lease_mutex);
                    return 1;  
                }
                pthread_mutex_unlock(&lease_mutex);
                return 0;  
            }
            pthread_mutex_unlock(&lease_mutex);
            return 1;  
        }
    }

    pthread_mutex_unlock(&lease_mutex);
    return 0;  
}


void *clean_expired_leases(void *arg) {
    while (1) {
        pthread_mutex_lock(&lease_mutex);

        time_t now = time(NULL);
        for (int i = 0; i < ip_table_size; i++) {
            if (ip_table[i].is_leased && ip_table[i].lease_expiry < now) {
                log_message("Lease expired for IP: %s", ip_table[i].ip);
                ip_table[i].is_leased = 0;
                memset(ip_table[i].mac, 0, sizeof(ip_table[i].mac));  
            }
        }

        pthread_mutex_unlock(&lease_mutex);
        sleep(60);  
    }
    return NULL;
}



void start_cleaner_thread() {
    pthread_t cleaner_thread;
    pthread_create(&cleaner_thread, NULL, clean_expired_leases, NULL);
    pthread_detach(cleaner_thread);
}

void process_dhcp_message(int sockfd, unsigned char *buffer, int len,
                          struct sockaddr_in *client_addr, DHCPConfig *config) {
    if (memcmp(&buffer[236], DHCP_MAGIC_COOKIE, 4) != 0) {
        log_message("Invalid DHCP magic cookie");
        return;
    }

    int i = 240;
    unsigned char msg_type = 0;
    while (i < len && buffer[i] != OPT_END) {
        if (buffer[i] == OPT_MSG_TYPE) {
            msg_type = buffer[i + 2];  
            break;
        }
        i += 2 + buffer[i + 1];  
    }

    log_message("Received DHCP message of type %d from client %02x:%02x:%02x:%02x:%02x:%02x",
                msg_type, buffer[28], buffer[29], buffer[30], buffer[31], buffer[32], buffer[33]);

    switch (msg_type) {
        case DHCP_DISCOVER:
            log_message("Processing DHCPDISCOVER");
            handle_discover(sockfd, buffer, client_addr, config);
            break;
        case DHCP_REQUEST:
            log_message("Processing DHCPREQUEST");
            handle_request(sockfd, buffer, client_addr, config);
            break;
        default:
            log_message("Unsupported or unexpected DHCP message type: %d", msg_type);
            break;
    }
}


void handle_discover(int sockfd, unsigned char *buffer, struct sockaddr_in *client_addr,
                     DHCPConfig *config) {
    unsigned char *client_mac = &buffer[28];
    char *offered_ip = allocate_ip(config, client_mac);

    if (offered_ip) {
        log_message("Offering IP %s to client %02x:%02x:%02x:%02x:%02x:%02x",
                    offered_ip, client_mac[0], client_mac[1], client_mac[2],
                    client_mac[3], client_mac[4], client_mac[5]);
        send_dhcp_packet(sockfd, client_addr, DHCP_OFFER, buffer, offered_ip, config);
    } else {
        log_message("No available IP addresses for client %02x:%02x:%02x:%02x:%02x:%02x",
                    client_mac[0], client_mac[1], client_mac[2],
                    client_mac[3], client_mac[4], client_mac[5]);
    }
}


void handle_request(int sockfd, unsigned char *buffer, struct sockaddr_in *client_addr,
                    DHCPConfig *config) {
    unsigned char *client_mac = &buffer[28];
    char requested_ip[16] = {0};  
    int i = 240;

    
    while (i < BUFFER_SIZE && buffer[i] != OPT_END) {
        if (buffer[i] == OPT_REQUESTED_IP) {
            snprintf(requested_ip, sizeof(requested_ip), "%d.%d.%d.%d",
                     buffer[i + 2], buffer[i + 3], buffer[i + 4], buffer[i + 5]);
            break;
        }
        i += 2 + buffer[i + 1];  
    }

    
    if (strlen(requested_ip) == 0 || !is_ip_available(requested_ip, client_mac)) {
        log_message("Requested IP %s is invalid or outside current range for client %02x:%02x:%02x:%02x:%02x:%02x",
                    requested_ip[0] ? requested_ip : "(null)", client_mac[0], client_mac[1],
                    client_mac[2], client_mac[3], client_mac[4], client_mac[5]);
        send_dhcp_packet(sockfd, client_addr, DHCP_NAK, buffer, NULL, config);
        return;
    }

    
    log_message("Acknowledging IP %s for client %02x:%02x:%02x:%02x:%02x:%02x",
                requested_ip, client_mac[0], client_mac[1], client_mac[2],
                client_mac[3], client_mac[4], client_mac[5]);
    send_dhcp_packet(sockfd, client_addr, DHCP_ACK, buffer, requested_ip, config);
}




void send_dhcp_packet(int sockfd, struct sockaddr_in *client_addr, unsigned char msg_type,
                      unsigned char *request_buffer, const char *yiaddr, DHCPConfig *config) {
    unsigned char response[BUFFER_SIZE] = {0};
    struct sockaddr_in broadcast_addr;
    int offset = 0;

    
    memset(&broadcast_addr, 0, sizeof(broadcast_addr));
    broadcast_addr.sin_family = AF_INET;
    broadcast_addr.sin_port = htons(DHCP_CLIENT_PORT);
    broadcast_addr.sin_addr.s_addr = INADDR_BROADCAST;

    
    response[offset++] = 0x02;  
    response[offset++] = 0x01;  
    response[offset++] = 0x06;  
    response[offset++] = 0x00;  

    
    memcpy(&response[offset], &request_buffer[4], 4);
    offset += 4;

    
    memset(&response[offset], 0, 4);
    offset += 4;

    
    memset(&response[offset], 0, 4);
    offset += 4;

    
    if (yiaddr != NULL) {
        struct in_addr addr;
        inet_pton(AF_INET, yiaddr, &addr);
        memcpy(&response[offset], &addr.s_addr, 4);
    }
    offset += 4;

    
    memset(&response[offset], 0, 4);
    offset += 4;

    
    memset(&response[offset], 0, 4);
    offset += 4;

    
    memcpy(&response[offset], &request_buffer[28], 16);  
    offset += 16;

    
    memset(&response[offset], 0, 64);
    offset += 64;

    
    memset(&response[offset], 0, 128);
    offset += 128;

    
    memcpy(&response[offset], DHCP_MAGIC_COOKIE, 4);
    offset += 4;

    
    unsigned char option_data[16];

    
    option_data[0] = msg_type;
    add_dhcp_option(response, &offset, OPT_MSG_TYPE, 1, option_data);

    
    struct in_addr server_id;
    inet_pton(AF_INET, config->server_identifier, &server_id);
    memcpy(option_data, &server_id.s_addr, 4);
    add_dhcp_option(response, &offset, OPT_SERVER_ID, 4, option_data);

    if (msg_type == DHCP_OFFER || msg_type == DHCP_ACK) {
        
        struct in_addr subnet;
        inet_pton(AF_INET, config->subnet_mask, &subnet);
        memcpy(option_data, &subnet.s_addr, 4);
        add_dhcp_option(response, &offset, OPT_SUBNET_MASK, 4, option_data);

        
        struct in_addr router;
        inet_pton(AF_INET, config->gateway, &router);
        memcpy(option_data, &router.s_addr, 4);
        add_dhcp_option(response, &offset, OPT_ROUTER, 4, option_data);

        
        struct in_addr dns;
        inet_pton(AF_INET, config->dns_server, &dns);
        memcpy(option_data, &dns.s_addr, 4);
        add_dhcp_option(response, &offset, OPT_DNS_SERVER, 4, option_data);

        
        uint32_t lease_time = htonl(config->lease_duration);
        memcpy(option_data, &lease_time, 4);
        add_dhcp_option(response, &offset, OPT_LEASE_TIME, 4, option_data);
    }

    
    response[offset++] = OPT_END;

    
    if (sendto(sockfd, response, offset, 0, (struct sockaddr *)&broadcast_addr,
           sizeof(broadcast_addr)) < 0) {
    log_message("Failed to send DHCP packet: %s", strerror(errno));
    } else {
    log_message("Sent DHCP %s to %s | Subnet=%s | Gateway=%s | Lease=%d | DNS=%s",
                msg_type == DHCP_OFFER ? "OFFER" : "ACK", yiaddr, config->subnet_mask,
                config->gateway, config->lease_duration, config->dns_server);
    }

}


void add_dhcp_option(unsigned char *packet, int *offset, unsigned char option,
                     unsigned char length, const unsigned char *data) {
    packet[*offset] = option;
    packet[*offset + 1] = length;
    memcpy(&packet[*offset + 2], data, length);
    *offset += length + 2;
}

void log_message(const char *format, ...) {
    time_t now;
    time(&now);
    char timestamp[26];
    ctime_r(&now, timestamp);
    timestamp[24] = '\0';  

    va_list args;
    va_start(args, format);

    char log_buffer[512];
    vsnprintf(log_buffer, sizeof(log_buffer), format, args);
    va_end(args);

    if (strstr(log_buffer, "Sent DHCP ACK to (null)")) {
        fprintf(stdout, "[%s] Warning: Invalid IP detected, skipping log entry.\n", timestamp);
        return;
    }

    fprintf(stdout, "[%s] %s\n", timestamp, log_buffer);
    fflush(stdout);
}

