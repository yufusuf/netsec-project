#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/udp.h>
#include <stdbool.h>

#define PORT 8888
#define PACKET_SIZE 256

void print_packet(unsigned char *buffer, int size, char *iface, bool is_outgoing);



unsigned short net_checksum_calculate(unsigned short *ptr, int nbytes) {
    long sum;
    unsigned short oddbyte;
    unsigned short answer;

    sum = 0;
    while (nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }

    if (nbytes == 1) {
        oddbyte = 0;
        *((unsigned char *)&oddbyte) = *(unsigned char *)ptr;
        sum += oddbyte;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = (unsigned short)~sum;

    return answer;
}

int main() {
    int sockfd;
    char buffer[PACKET_SIZE];
    struct sockaddr_in addr, src_addr;
    socklen_t addr_len = sizeof(struct sockaddr_in);

    const char *source_ip = getenv("SECURENET_HOST_IP");
    if (source_ip == NULL) {
        fprintf(stderr, "Environment variable SECURENET_HOST_IP not set\n");
        exit(EXIT_FAILURE);
    }

    if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP)) < 0) {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(PORT);

    while (1) {
        memset(buffer, 0, PACKET_SIZE);
        int n = recvfrom(sockfd, buffer, PACKET_SIZE, 0, (struct sockaddr *)&src_addr, &addr_len);
        if (n < 0) {
            perror("recvfrom failed");
            continue;
        }

        
        struct udphdr *udp_header = (struct udphdr *)(buffer);
        char *data = buffer  + sizeof(struct udphdr);
        
        print_packet(buffer, n, "eth0", false);

        // Swap source and destination addresses
        struct sockaddr_in dest_addr;
        dest_addr.sin_family = AF_INET;
        dest_addr.sin_addr.s_addr = src_addr.sin_addr.s_addr;
        dest_addr.sin_port = udp_header->uh_sport;

        udp_header->uh_dport = udp_header->uh_sport;
        udp_header->uh_sport = htons(PORT);

        // Recalculate checksums
        udp_header->uh_sum = 0;

    
        // UDP checksum
        struct pseudo_header {
            u_int32_t source_address;
            u_int32_t dest_address;
        };

        struct pseudo_header psh;
        psh.source_address = inet_addr(source_ip);
        psh.dest_address = dest_addr.sin_addr.s_addr;

        int psize = sizeof(struct pseudo_header) + n;
        char *pseudogram = malloc(psize);

        memcpy(pseudogram, (char *)&psh, sizeof(struct pseudo_header));
        memcpy(pseudogram + sizeof(struct pseudo_header), udp_header, n);

        udp_header->uh_sum = net_checksum_calculate((unsigned short *)pseudogram, psize);

        free(pseudogram);

        print_packet(buffer, n, "eth0", true);

        if (sendto(sockfd, buffer, n, 0, (struct sockaddr *)&dest_addr, addr_len) < 0) {
            perror("sendto failed");
        } else {
            printf("Response sent to %s:%d\n", inet_ntoa(dest_addr.sin_addr), ntohs(dest_addr.sin_port));
        }
    }

    close(sockfd);
    return 0;
}


void print_packet(unsigned char *buffer, int size, char *iface, bool is_outgoing) {
    struct udphdr *udph = (struct udphdr *) buffer;
    char *data = buffer + sizeof(struct udphdr);

    if (is_outgoing)
        printf("Packet from %s UDP Header:\n", iface);
    else
        printf("Packet to %s UDP Header:\n", iface);
    printf("   |-Source Port       : %d\n", ntohs(udph->uh_sport));
    printf("   |-Destination Port  : %d\n", ntohs(udph->uh_dport));
    printf("   |-UDP Length        : %d\n", ntohs(udph->uh_ulen));
    printf("   |-UDP Checksum      : %d\n", ntohs(udph->uh_sum));
    /*
    printf("   |-Payload           : ");
    for (int i = 0; i < size - sizeof(struct udphdr);i++) {
        if (data[i] >= 32 && data[i] <= 126) {
            printf("%c", buffer[i]);
        } 
    }
    printf("\n");
    */
}
