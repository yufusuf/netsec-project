#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <openssl/hmac.h>
#include <pcap.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../cc_headers/aux.h"
#include "../../cc_headers/covert_channel.h"

struct covert_channel *cc;
int packet_count = 0;
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
void packet_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    struct iphdr *ip = (struct iphdr *)(bytes + sizeof(struct ethhdr)); // Skip Ethernet header
    unsigned char *buffer;
    unsigned int packet_size;
    if (ip->protocol != IPPROTO_TCP)
        return;
    // calculate total packet size with eth header
    packet_size = ntohs(ip->tot_len) + sizeof(struct ethhdr);
    buffer = malloc(packet_size * sizeof(unsigned char));
    memcpy(buffer, bytes, packet_size);

    pthread_mutex_lock(&mutex);
    // printf("##########################################\n");
    // print_packet(buffer, packet_size, "eth0", 0);
    if (!cc->done)
        decode_packet(cc, buffer);
    else {
        exit(0);
    }
    // printf("##########################################\n");
    pthread_mutex_unlock(&mutex);
    // print_packet(buffer, packet_size, "eth0", 0);
}

int main(int argc, char *argv[]) {

    char *dev = "eth0";
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    const char *secret_key = getenv("SECRET_KEY");
    cc = init_covert_channel(secret_key, 32, 3);
    ;

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        fprintf(stderr, "pcap_open_live failed: %s\n", errbuf);
        return 1;
    }

    struct bpf_program fp;
    char filter_exp[] = "tcp and ip dst host 10.0.0.21";
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1 || pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Failed to set filter.\n");
        return 1;
    }

    printf("Listening on interface %s for TCP packets...\n", dev);
    pcap_loop(handle, -1, packet_handler, NULL);

    pcap_close(handle);
    return 0;
}
