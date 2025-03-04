#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

#define PORT 8888
#define BUFFER_SIZE 65536
#define PACKET_SIZE 512

void error(const char *msg) {
    perror(msg);
    exit(EXIT_FAILURE);
}

int main() {
    int sockfd;
    struct sockaddr_in server_addr, client_addr;
    char buffer[BUFFER_SIZE];
    char sendbuffer[PACKET_SIZE];
    socklen_t client_len = sizeof(client_addr);
    // Get environment variable INSECURENET_HOST_IP
    char *host_ip = getenv("INSECURENET_HOST_IP");
    if (host_ip == NULL) {
        error("Environment variable INSECURENET_HOST_IP not set");
    }

    // Create a classical UDP socket and bind to PORT to AVOID Icmp Error Packets
    int udp_sockfd;
    if ((udp_sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        error("UDP socket creation failed");
    }
    // Set the UDP socket receive buffer size to zero
    int rcvbuf = 0;
    if (setsockopt(udp_sockfd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf)) < 0) {
        perror("setsockopt SO_RCVBUF failed");
    }
    // Bind the UDP socket to the port
    if (bind(udp_sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        error("UDP bind failed");
    }


    // Create raw socket
    if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP)) < 0) {
        error("socket creation failed");
    }

    // Bind the socket to the port
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(host_ip);
    server_addr.sin_port = htons(PORT);

    if (bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        error("bind failed");
    }

    while (1) {
        // Receive UDP packet
        ssize_t data_len = recvfrom(sockfd, buffer, BUFFER_SIZE, 0, (struct sockaddr *)&client_addr, &client_len);
        if (data_len < 0) {
            error("recvfrom failed");
        }

        // Print received message
        struct iphdr *ip_header = (struct iphdr *)buffer;
        struct udphdr *udp_header = (struct udphdr *)(buffer + sizeof(struct iphdr));
        char *data = (char *)(buffer + sizeof(struct iphdr) + sizeof(struct udphdr));
        data[data_len - sizeof(struct udphdr)] = '\0';

        client_addr.sin_family = AF_INET;
        client_addr.sin_port = udp_header->source;
        client_addr.sin_addr.s_addr = ip_header->saddr;
        printf("Received from %s:%d (length: %ld ) %s\n", inet_ntoa(*(struct in_addr *)&ip_header->saddr), ntohs(udp_header->source), data_len, data);
        printf("Received from %s:%d (length: %ld ) %s\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port), data_len, data);
        
        // Respond to the message
        char response[] = "Message received";
        ssize_t response_len = strlen(response);

        // Create response packet
        struct udphdr *resp_udp_header = (struct udphdr *)(sendbuffer);
        char *resp_data = sendbuffer + sizeof(struct udphdr);
        // Fill UDP header
        resp_udp_header->source = htons(PORT);
        resp_udp_header->dest = udp_header->source;
        resp_udp_header->len = htons(sizeof(struct udphdr) + response_len);
        resp_udp_header->check = 0;

        // Fill data
        memcpy(resp_data, response, response_len);

        // COMPUTE UDP CHECKSUM

        // Send response
        if (sendto(sockfd, sendbuffer, sizeof(struct udphdr) + response_len, 0, (struct sockaddr *)&client_addr, client_len) < 0) {
            error("sendto failed");
        }
    }

    close(sockfd);

    // Close the UDP socket as it is only used to avoid ICMP packets
    close(udp_sockfd);
    return 0;
}