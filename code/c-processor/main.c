#include "../cc_headers/aux.h"
#include "../cc_headers/covert_channel.h"
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
#include <pcap.h>
#include <pthread.h>
#include <string.h>
#include <time.h>

#define INCOMING_PACKET_BUFSIZE 65535
struct covert_channel *cc;
int sent_packets = 0;
int drop_rate = 0;

pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static pcap_dumper_t *pcap_dumper = NULL;
static pcap_t *pcap_handle = NULL;

/* put the current wall‑clock into a pcap header */
static inline void fill_hdr(struct pcap_pkthdr *hdr, uint32_t len) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    hdr->ts = tv;
    hdr->caplen = len;
    hdr->len = len;
}
void mitigate_packet(unsigned char *data) {
    struct iphdr *iph = (struct iphdr *)(data + sizeof(struct ethhdr));
    struct tcphdr *tcph = (struct tcphdr *)(data + iph->ihl * 4 + sizeof(struct ethhdr));

    // set tsvals last bit to 0
    uint32_t *tsval = get_tcp_timestamp(tcph);
    if (tsval) {
        uint32_t v = ntohl(*tsval);
        v &= ~1U;
        *tsval = htonl(v);
    }
    unsigned short checksum = compute_tcp_checksum(data);
    tcph->check = checksum;
}

void handle_nats_packets(natsConnection *conn, natsSubscription *sub, natsMsg *msg, void *closure) {
    natsStatus s;
    size_t len = natsMsg_GetDataLength(msg);
    uint8_t *data = (uint8_t *)natsMsg_GetData(msg);
    char outiface[5];
    // before sending the packets sleep for the exponentially random amount of
    // time double lambda = 10000000; double sleep_time = get_expo_random(lambda);
    // usleep((double)(sleep_time * 1e6));

    struct iphdr *iph = (struct iphdr *)(data + sizeof(struct ethhdr));
    struct tcphdr *tcph = (struct tcphdr *)(data + iph->ihl * 4 + sizeof(struct ethhdr));
    unsigned short checksum = compute_tcp_checksum(data);
    tcph->check = checksum;

    // print ts value
    if (strcmp(natsMsg_GetSubject(msg), "inpktsec") == 0) {
        strncpy(outiface, "eth1", 5);
        if (iph->protocol == IPPROTO_TCP) {
            pthread_mutex_lock(&mutex);
            if (!cc->done && !tcph->syn && !tcph->fin && !tcph->rst) {
                encode_packet(cc, data);
                sent_packets++;
            }
            else if (cc->done) {
                printf("message sent in %d packets\n", sent_packets);
                exit(0);
            }
            pthread_mutex_unlock(&mutex);
            // with %drop_rate chance drop the packet
            if (rand() % 100 < drop_rate) {
                return;
            }
        }
        // hypothethically, we can mitigate packets here
        // mitigate_packet(data);

        // for capturing pcap
        // struct pcap_pkthdr hdr;
        // fill_hdr(&hdr, (uint32_t)len);

        /* reuse the same mutex you already declared */
        // pthread_mutex_lock(&mutex);
        // pcap_dump((u_char *)pcap_dumper, &hdr, data);
        // pthread_mutex_unlock(&mutex);

        // print_packet(data, len, outiface, true);
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
    natsMsg_Destroy(msg);
}

int main(int argc, char *argv[]) {
    natsConnection *conn = NULL;
    natsOptions *opts = NULL;
    natsStatus s;
    natsSubscription *sub_inpktsec = NULL;
    natsSubscription *sub_inpktinsec = NULL;
    char *nats_url = getenv("NATS_SURVEYOR_SERVERS");
    const char *secret_key = getenv("SECRET_KEY");
    int occupation = 3;
    srand(time(NULL));
    // read drop rate from args
    //
    if (argc > 2) {
        drop_rate = atoi(argv[1]);
        if (drop_rate < 0 || drop_rate > 100) {
            fprintf(stderr, "Invalid drop rate. Must be between 0 and 100.\n");
            return 1;
        }
        occupation = atoi(argv[2]);
    }
    else {
        fprintf(stderr, "Usage: %s <drop_rate> <occupation_number>\n", argv[0]);
        return 1;
    }

    cc = init_covert_channel(secret_key, 32, occupation);
    init_message_from_file(cc, "sonnet.txt");

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
    // pcap_handle = pcap_open_dead(DLT_EN10MB, 65535);
    // if (pcap_handle == NULL) {
    //     fprintf(stderr, "pcap_open_dead failed\n");
    //     return 1;
    // }
    // pcap_dumper = pcap_dump_open(pcap_handle, "capture.pcap");
    // if (pcap_dumper == NULL) {
    //     fprintf(stderr, "pcap_dump_open: %s\n", pcap_geterr(pcap_handle));
    //     return 1;
    // }
    s = natsConnection_Subscribe(&sub_inpktsec, conn, "inpktsec", handle_nats_packets, NULL);
    s = natsConnection_Subscribe(&sub_inpktinsec, conn, "inpktinsec", handle_nats_packets, NULL);

    while (true)
        ;

    return 0;
}
