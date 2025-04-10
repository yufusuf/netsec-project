#include "aux.h"
#include "covert_channel.h"
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <nats/nats.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netpacket/packet.h>
#include <openssl/evp.h>
#include <string.h>
#include <time.h>

#define INCOMING_PACKET_BUFSIZE 65535
struct covert_channel *cc;
void handle_nats_packets(natsConnection *conn, natsSubscription *sub, natsMsg *msg, void *closure) {
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
        if (!cc->done && !tcph->syn)
            encodePacket(cc, data);
        unsigned short checksum = compute_tcp_checksum(data);
        tcph->check = checksum;
    }

    // print ts value
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
    // print_packet(data, len, outiface, true);
}

int main(int argc, char *argv[]) {
    natsConnection *conn = NULL;
    natsOptions *opts = NULL;
    natsStatus s;
    natsSubscription *sub_inpktsec = NULL;
    natsSubscription *sub_inpktinsec = NULL;
    char *nats_url = getenv("NATS_SURVEYOR_SERVERS");
    const char *secret_key = getenv("SECRET_KEY");
    cc = init_covert_channel(secret_key, 32);

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
