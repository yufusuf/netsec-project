#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/udp.h>
#include <netinet/ip.h>

#define DEST_PORT 8888
#define SRC_PORT 8888
#define PACKET_SIZE 512

unsigned short checksum(void *b, int len) {    
    unsigned short *buf = b;
    unsigned int sum = 0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2)
        sum += *buf++;
    if (len == 1)
        sum += *(unsigned char *)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

int main() {
    int sockfd;
    char buffer[PACKET_SIZE];
    struct sockaddr_in dest_addr;
    struct udphdr *udph = (struct udphdr *) (buffer);
    char *data = buffer +  sizeof(struct udphdr);
    const char *dest_ip = getenv("INSECURENET_HOST_IP");
    const char *src_ip = getenv("SECURENET_HOST_IP");

    if (dest_ip == NULL) {
        fprintf(stderr, "Environment variable INSECURENET_HOST_IP not set\n");
        return 1;
    }

    if (src_ip == NULL) {
        fprintf(stderr, "Environment variable SECURENET_HOST_IP not set\n");
        return 1;
    }

    struct sockaddr_in src_addr;
    src_addr.sin_family = AF_INET;
    src_addr.sin_port = htons(SRC_PORT);
    src_addr.sin_addr.s_addr = inet_addr(src_ip);

    // Create a classical UDP socket and bind to PORT to AVOID Icmp Error Packets
    int udp_sockfd;
    if ((udp_sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("UDP socket creation failed");
    }
    // Set the UDP socket receive buffer size to zero
    int rcvbuf = 0;
    if (setsockopt(udp_sockfd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf)) < 0) {
        perror("setsockopt SO_RCVBUF failed");
    }
    // Bind the UDP socket to the port
    if (bind(udp_sockfd, (struct sockaddr *)&src_addr, sizeof(src_addr)) < 0) {
        perror("UDP bind failed");
    }


    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (sockfd < 0) {
        perror("socket");
        return 1;
    }


    if (bind(sockfd, (struct sockaddr *)&src_addr, sizeof(src_addr)) < 0) {
        perror("bind");
        close(sockfd);
        return 1;
    }

    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(DEST_PORT);
    dest_addr.sin_addr.s_addr = inet_addr(dest_ip);

    memset(buffer, 0, PACKET_SIZE);
    udph->source = htons(SRC_PORT);
    udph->dest = htons(DEST_PORT);
    udph->len = htons(PACKET_SIZE);
    udph->check = 0;

    strcpy(data, "Hello, this is a raw socket UDP packet!");

    while (1) {
        if (sendto(sockfd, buffer, PACKET_SIZE, 0, (struct sockaddr *) &dest_addr, sizeof(dest_addr)) < 0) {
            perror("sendto");
            close(sockfd);
            return 1;
        }

        printf("Packet sent to %s:%d\n", dest_ip, DEST_PORT);
        char recv_buffer[PACKET_SIZE];
        socklen_t addr_len = sizeof(dest_addr);
        int recv_len = recvfrom(sockfd, recv_buffer, PACKET_SIZE, 0, (struct sockaddr *) &dest_addr, &addr_len);
        if (recv_len < 0) {
            perror("recvfrom");
            close(sockfd);
            return 1;
        }
        char *data = (char *)(recv_buffer + sizeof(struct iphdr) + sizeof(struct udphdr));
        data[recv_len - sizeof(struct udphdr)] = '\0';
        printf("Received response: %s\n", data);
        sleep(1);
    }

    close(sockfd);
    // Close the UDP socket as it is only used to avoid ICMP packets
    close(udp_sockfd);
    return 0;
}