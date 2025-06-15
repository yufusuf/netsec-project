#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <openssl/hmac.h>
#include <pcap.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../cc_headers/aux.h"
#include "../../cc_headers/covert_channel.h"

struct covert_channel *cc;
int packet_count = 0;
void packet_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    struct iphdr *ip = (struct iphdr *)(bytes + sizeof(struct ethhdr)); // Skip Ethernet header
    unsigned char *buffer;
    unsigned int packet_size;

    pcap_dump(user, h, bytes);
    packet_size = ntohs(ip->tot_len) + sizeof(struct ethhdr);
    buffer = malloc(packet_size * sizeof(unsigned char));
    memcpy(buffer, bytes, packet_size);

    if (!cc->done)
        decode_packet(cc, buffer);
    else {
        // exit(0);
    }
    free(buffer);
}

int main(int argc, char *argv[]) {

    char *dev = "eth0";
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    pcap_dumper_t *dumper;
    const char *outfile = "capture.pcap";

    const char *secret_key = getenv("SECRET_KEY");
    cc = init_covert_channel(secret_key, 32, 3);

    int total_blocks = 100;

    cc->message = malloc(total_blocks * sizeof(unsigned char *));

    for (int i = 0; i < total_blocks; i++) {
        cc->message[i] = calloc(BLOCKSIZE / 8, sizeof(unsigned char));
    }
    cc->done = 0;
    cc->block_len = 30;

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        fprintf(stderr, "pcap_open_live failed: %s\n", errbuf);
        return 1;
    }

    dumper = pcap_dump_open(handle, outfile);
    if (!dumper) {
        fprintf(stderr, "pcap_dump_open failed: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return 1;
    }

    struct bpf_program fp;
    char filter_exp[] = "tcp and ip dst host 10.0.0.21";
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1 || pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Failed to set filter.\n");
        return 1;
    }

    printf("Listening on interface %s for TCP packets...\n", dev);
    pcap_loop(handle, -1, packet_handler, (u_char *)dumper);

    pcap_close(handle);
    return 0;
}
