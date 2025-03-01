#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
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
    int counter = 0;
    int n;
    char buffer[PACKET_SIZE];
    struct sockaddr_in dest_addr;
    struct sockaddr_in client_addr;

    // We create a fixed size UDP datagram of size PACKET_SIZE including everything
    struct udphdr *udph = (struct udphdr *) buffer;
    // Payload of UDP is after the UDP header, pointer to is the data
    char *data = buffer + sizeof(struct udphdr);

    const char *dest_ip = getenv("INSECURENET_HOST_IP");
    if (dest_ip == NULL) {
        fprintf(stderr, "Environment variable INSECURENET_HOST_IP not set\n");
        exit(EXIT_FAILURE);
    }
    const char *source_ip = getenv("SECURENET_HOST_IP");
    if (source_ip == NULL) {
        fprintf(stderr, "Environment variable SECURENET_HOST_IP not set\n");
        exit(EXIT_FAILURE);
    }

    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (sockfd < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(PORT);
    dest_addr.sin_addr.s_addr = inet_addr(dest_ip);

    while (1) {
        memset(buffer, 0, PACKET_SIZE);

        // Fill in the UDP Header
        udph->uh_sport = htons(PORT);
        udph->uh_dport = htons(PORT);
        udph->uh_ulen = htons(PACKET_SIZE);
        udph->uh_sum = 0;

        // Set data
        //char message_with_counter[50];
        //snprintf(message_with_counter, sizeof(message_with_counter), "hello insec, pkt %d", counter++);
        //memcpy(data, message_with_counter, strlen(message_with_counter));
        
        
        // UDP checksum
        struct pseudo_header {
            u_int32_t source_address;
            u_int32_t dest_address;
        };

        struct pseudo_header psh;
        struct in_addr f;
        f.s_addr = inet_addr(source_ip);
        psh.source_address = f.s_addr;
        psh.dest_address = dest_addr.sin_addr.s_addr;

        int psize = sizeof(struct pseudo_header) + PACKET_SIZE;
        char *pseudogram = malloc(psize);

        memcpy(pseudogram, (char *)&psh, sizeof(struct pseudo_header));
        memcpy(pseudogram + sizeof(struct pseudo_header), udph, PACKET_SIZE);

        udph->uh_sum = net_checksum_calculate((unsigned short *)pseudogram, psize);

        free(pseudogram);

        print_packet(buffer, PACKET_SIZE, "eth0", true);

        if (sendto(sockfd, buffer, PACKET_SIZE, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) < 0) {
            perror("sendto");
            close(sockfd);
            exit(EXIT_FAILURE);
        }

        // Receive response
        socklen_t len = sizeof(client_addr);
        if (n = recvfrom(sockfd, buffer, PACKET_SIZE, 0, (struct sockaddr *)&client_addr, &len) < 0) {
            perror("recvfrom");
            close(sockfd);
            exit(EXIT_FAILURE);
        }

        print_packet(buffer, n, "eth0", false);

        sleep(1); // Send packet every second
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
