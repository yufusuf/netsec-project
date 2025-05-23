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
void receive_packet(struct covert_channel *cc, unsigned char *buffer) {
    struct iphdr *iph = (struct iphdr *)(buffer + sizeof(struct ethhdr));
    struct tcphdr *tcph = (struct tcphdr *)(buffer + iph->ihl * 4 + sizeof(struct ethhdr));
    int tcp_header_len = (unsigned int)tcph->doff * 4;

    packet_count++;
    if (tcph->syn || tcph->fin || tcph->rst) {
        return;
    }

    unsigned char digest[EVP_MAX_MD_SIZE] = {0};
    unsigned int digest_len = 0;
    unsigned char bit_index;
    unsigned char key_bit;
    unsigned char plain_text_bit;
    unsigned char cipher_text_bit;
    uint32_t crc;
    uint32_t *tsval;

    HMAC(EVP_sha256(), cc->shared_key, sizeof(cc->shared_key), (unsigned char *)tcph, sizeof(struct tcphdr), digest,
         &digest_len);

    // for (int i = 0; i < tcp_header_len; i++) {
    //     printf("%02x ", ((unsigned char *)tcph)[i]);
    // }
    // printf("\n");
    bit_index = get_bit_index(digest, digest_len);
    key_bit = get_key_bit(digest, digest_len);
    tsval = get_tcp_timestamp(tcph);
    if (tsval == NULL) {
        printf("No timestamp option found\n");
        return;
    }
    cipher_text_bit = ntohl(*tsval) & 1;
    plain_text_bit = key_bit ^ cipher_text_bit;
    // plain_text_bit = cipher_text_bit;
    cc->message[bit_index / 8] |= (plain_text_bit << (7 - (bit_index % 8)));
    // printf("Digest: ");
    // for (int i = 0; i < digest_len; i++) {
    //     printf("%02x", digest[i]);
    // }
    // // print received bits
    // printf("\n");
    // printf("Bit index: %d, Key bit: %d, Plain text bit: %d, Cipher text bit: %d, TSVAL: %u\n", bit_index, key_bit,
    //        plain_text_bit, cipher_text_bit, ntohl(*tsval));
    crc = crc32(cc->message, BLOCKSIZE / 8 - CHECKSUM_SIZE / 8);
    printf("\r\033[Kmessage:%.28s crc: 0x%08X\n", cc->message, crc);
    fflush(stdout);
    // validate crc
    if (crc != 0 &&
        (memcmp((uint32_t *)(cc->message + BLOCKSIZE / 8 - CHECKSUM_SIZE / 8), &crc, CHECKSUM_SIZE / 8) == 0)) {
        printf("\r");
        printf("BLOCK RECEIVED in %d packets\n", packet_count);
        printf("received message: ");
        for (int i = 0; i < BLOCKSIZE / 8 - CHECKSUM_SIZE / 8; i++) {
            printf("%c", cc->message[i]);
        }
        printf("\n");
        cc->done = 1;
    }
}
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
    if (!cc->done)
        receive_packet(cc, buffer);
    else {
        exit(0);
    }
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
