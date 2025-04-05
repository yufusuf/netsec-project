#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <math.h>
#include <nats/nats.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netpacket/packet.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define INCOMING_PACKET_BUFSIZE 65535
double get_expo_random(double lambda)
{
    double u;
    u = rand() / (RAND_MAX + 1.0);
    return -log(1 - u) / lambda;
}
double read_tcp_timestamp(struct tcphdr *tcph)
{
    int i;
    unsigned int tcp_header_len;
    unsigned int options_len;
    unsigned char *options;
    unsigned char kind;
    unsigned int option_len;
    uint32_t tsval;

    tcp_header_len = (unsigned int)tcph->doff * 4;
    if (tcp_header_len <= 20)
        return -1;

    options = (unsigned char *)(tcph + 20);
    options_len = tcp_header_len - 20;

    i = 0;
    while (i < options_len) {
        kind = options[i];
        if (kind == TCPOPT_EOL)
            break;
        else if (kind == TCPOPT_NOP) {
            i++;
            continue;
        }
        else {
            option_len = options[i + 1];
            if (kind == TCPOPT_TIMESTAMP) {
                if (i + 1 >= options_len)
                    break;
                tsval = ntohl(*(uint32_t *)(options + i + 2));
                return tsval;
            }
            i += option_len;
        }
    }
    return -1;
}
unsigned short compute_tcp_checksum(unsigned char *buffer)
{
    // code taken from https://gist.github.com/david-hoze/0c7021434796997a4ca42d7731a7073a
    struct iphdr *iph = (struct iphdr *)(buffer + sizeof(struct ethhdr));
    struct tcphdr *tcph = (struct tcphdr *)(buffer + iph->ihl * 4 + sizeof(struct ethhdr));
    register unsigned long sum = 0;
    unsigned short tcp_len = ntohs(iph->tot_len) - (iph->ihl << 2);
    unsigned short *ip_payload = (unsigned short *)(tcph);
    // add the pseudo header
    // the source ip
    sum += (iph->saddr >> 16) & 0xFFFF;
    sum += (iph->saddr) & 0xFFFF;
    // the dest ip
    sum += (iph->daddr >> 16) & 0xFFFF;
    sum += (iph->daddr) & 0xFFFF;
    // protocol and reserved: 6
    sum += htons(IPPROTO_TCP);
    // the length
    sum += htons(tcp_len);

    // add the IP payload
    // initialize checksum to 0
    tcph->check = 0;
    while (tcp_len > 1) {
        sum += *ip_payload++;
        tcp_len -= 2;
    }
    // if any bytes left, pad the bytes and add
    if (tcp_len > 0) {
        sum += ((*ip_payload) & htons(0xFF00));
    }
    // Fold 32-bit sum to 16 bits: add carrier to result
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum = ~sum;
    return sum;
}
void print_packet(unsigned char *buffer, int size, char *iface, bool is_outgoing)
{
    struct ethhdr *eth = (struct ethhdr *)buffer;

    if (ntohs(eth->h_proto) == ETH_P_IP) {
        struct iphdr *iph = (struct iphdr *)(buffer + sizeof(struct ethhdr));
        if (is_outgoing)
            printf("Packet from %s IP Header:\n", iface);
        else
            printf("Packet to %s IP Header:\n", iface);
        printf("   |-IP Version        : %d\n", (unsigned int)iph->version);
        printf("   |-IP Header Length  : %d DWORDS or %d Bytes\n", (unsigned int)iph->ihl,
               ((unsigned int)(iph->ihl)) * 4);
        printf("   |-Type Of Service   : %d\n", (unsigned int)iph->tos);
        printf("   |-IP Total Length   : %d Bytes(Size of Packet)\n", ntohs(iph->tot_len));
        printf("   |-Identification    : %d\n", ntohs(iph->id));
        printf("   |-TTL               : %d\n", (unsigned int)iph->ttl);
        printf("   |-Protocol          : %d\n", (unsigned int)iph->protocol);
        printf("   |-Checksum          : %d\n", ntohs(iph->check));
        printf("   |-Source IP         : %s\n", inet_ntoa(*(struct in_addr *)&iph->saddr));
        printf("   |-Destination IP    : %s\n", inet_ntoa(*(struct in_addr *)&iph->daddr));

        if (iph->protocol == IPPROTO_TCP) {
            struct tcphdr *tcph = (struct tcphdr *)(buffer + iph->ihl * 4 + sizeof(struct ethhdr));
            printf("TCP Header:\n");
            printf("   |-Source Port       : %u\n", ntohs(tcph->source));
            printf("   |-Destination Port  : %u\n", ntohs(tcph->dest));
            printf("   |-Sequence Number   : %u\n", ntohl(tcph->seq));
            printf("   |-Acknowledge Number: %u\n", ntohl(tcph->ack_seq));
            printf("   |-Header Length     : %d DWORDS or %d Bytes\n", (unsigned int)tcph->doff,
                   (unsigned int)tcph->doff * 4);
            printf("   |-Urgent Flag       : %d\n", (unsigned int)tcph->urg);
            printf("   |-Acknowledgement Flag : %d\n", (unsigned int)tcph->ack);
            printf("   |-Push Flag         : %d\n", (unsigned int)tcph->psh);
            printf("   |-Reset Flag        : %d\n", (unsigned int)tcph->rst);
            printf("   |-Synchronise Flag  : %d\n", (unsigned int)tcph->syn);
            printf("   |-Finish Flag       : %d\n", (unsigned int)tcph->fin);
            printf("   |-Window            : %d\n", ntohs(tcph->window));
            printf("   |-Checksum          : %d\n", ntohs(tcph->check));
            printf("   |-Urgent Pointer    : %d\n", tcph->urg_ptr);
            printf("   |-TIME STAMP        : %f\n", read_tcp_timestamp(tcph));
        }
        else if (iph->protocol == IPPROTO_UDP) {
            struct udphdr *udph = (struct udphdr *)(buffer + iph->ihl * 4 + sizeof(struct ethhdr));
            printf("UDP Header:\n");
            printf("   |-Source Port       : %d\n", ntohs(udph->source));
            printf("   |-Destination Port  : %d\n", ntohs(udph->dest));
            printf("   |-UDP Length        : %d\n", ntohs(udph->len));
            printf("   |-UDP Checksum      : %d\n", ntohs(udph->check));
        }
        else if (iph->protocol == IPPROTO_ICMP) {
            struct icmphdr *icmph = (struct icmphdr *)(buffer + iph->ihl * 4 + sizeof(struct ethhdr));
            printf("ICMP Header:\n");
            printf("   |-Type              : %d\n", (unsigned int)(icmph->type));
            printf("   |-Code              : %d\n", (unsigned int)(icmph->code));
            printf("   |-Checksum          : %d\n", ntohs(icmph->checksum));
            printf("   |-ID                : %d\n", ntohs(icmph->un.echo.id));
            printf("   |-Sequence          : %d\n", ntohs(icmph->un.echo.sequence));
        }
    }

    const char *protocol_name;
    switch (ntohs(eth->h_proto)) {
    case ETH_P_IP:
        protocol_name = "IP";
        break;
    case ETH_P_ARP:
        protocol_name = "ARP";
        break;
    case ETH_P_IPV6:
        protocol_name = "IPv6";
        break;
    default:
        protocol_name = "Unknown";
        break;
    }

    const char *iface_type;
    if (strcmp(iface, "eth1") == 0) {
        iface_type = "sec";
    }
    else if (strcmp(iface, "eth2") == 0) {
        iface_type = "ins";
    }
    else {
        iface_type = "unknown";
    }

    printf("Interface: %s (%s), %s SMAC: %02x:%02x:%02x:%02x:%02x:%02x, DMAC: %02x:%02x:%02x:%02x:%02x:%02x, Protocol: "
           "%s\n",
           iface, iface_type, is_outgoing ? "Outgoing" : "Incoming", eth->h_source[0], eth->h_source[1],
           eth->h_source[2], eth->h_source[3], eth->h_source[4], eth->h_source[5], eth->h_dest[0], eth->h_dest[1],
           eth->h_dest[2], eth->h_dest[3], eth->h_dest[4], eth->h_dest[5], protocol_name);
}
void handle_nats_packets(natsConnection *conn, natsSubscription *sub, natsMsg *msg, void *closure)
{
    natsStatus s;
    size_t len = natsMsg_GetDataLength(msg);
    uint8_t *data = (uint8_t *)natsMsg_GetData(msg);
    char outiface[5];
    // before sending the packets sleep for the exponentially random amount of time
    // double lambda = 10000000;
    // double sleep_time = get_expo_random(lambda);
    // usleep((double)(sleep_time * 1e6));

    struct iphdr *iph = (struct iphdr *)(data + sizeof(struct ethhdr));
    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = (struct tcphdr *)(data + iph->ihl * 4 + sizeof(struct ethhdr));
        unsigned short checksum = compute_tcp_checksum(data);
        tcph->check = checksum;
    }
    if (strcmp(natsMsg_GetSubject(msg), "inpktsec") == 0) {
        strncpy(outiface, "eth1", 5);

        s = natsConnection_Publish(conn, "outpktinsec", data, len);
        if (s != NATS_OK) {
            fprintf(stderr, "Error publishing packet to NATS: %s\n", natsStatus_GetText(s));
        }
    }
    else if (strcmp(natsMsg_GetSubject(msg), "inpktinsec") == 0) {
        strncpy(outiface, "eth2", 5);
        s = natsConnection_Publish(conn, "outpktsec", data, len);
        if (s != NATS_OK) {
            fprintf(stderr, "Error publishing packet to NATS: %s\n", natsStatus_GetText(s));
        }
    }
    print_packet(data, len, outiface, true);
}
int main(int argc, char *argv[])
{
    natsConnection *conn = NULL;
    natsOptions *opts = NULL;
    natsStatus s;
    natsSubscription *sub_inpktsec = NULL;
    natsSubscription *sub_inpktinsec = NULL;
    char *nats_url = getenv("NATS_SURVEYOR_SERVERS");
    srand(time(NULL));

    s = natsOptions_Create(&opts);
    if (s == NATS_OK) {
        s = natsOptions_SetURL(opts, nats_url);
    }
    if (s == NATS_OK) {
        s = natsConnection_Connect(&conn, opts);
    }
    if (s != NATS_OK) {
        fprintf(stderr, "Error connecting to NATS: %s\n", natsStatus_GetText(s));
        return 1;
    }

    s = natsConnection_Subscribe(&sub_inpktsec, conn, "inpktsec", handle_nats_packets, NULL);
    s = natsConnection_Subscribe(&sub_inpktinsec, conn, "inpktinsec", handle_nats_packets, NULL);

    while (true)
        ;

    return 0;
}
