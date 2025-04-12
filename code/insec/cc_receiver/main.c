#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <pcap.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../cc_headers/aux.h"
#include "../../cc_headers/covert_channel.h"
#define EXPECTED_BLOCKS 200
struct covert_channel *cc;
void receive_packet(struct covert_channel *cc, unsigned char *buffer) {
    struct iphdr *iph = (struct iphdr *)(buffer + sizeof(struct ethhdr));
    struct tcphdr *tcph = (struct tcphdr *)(buffer + iph->ihl * 4 + sizeof(struct ethhdr));
    int tcp_header_len = (unsigned int)tcph->doff * 4;

    if (tcph->syn || tcph->fin || tcph->rst) {
        return;
    }

    unsigned char digest[EVP_MAX_MD_SIZE] = {0};
    unsigned int digest_len = 0;
    unsigned char bit_index;
    unsigned char key_bit;
    unsigned char plain_text_bit;
    unsigned char cipher_text_bit;
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
    cc->message[cc->block_index][bit_index / 8] |= (plain_text_bit << (7 - (bit_index % 8)));

    // verify crc32 checksum
    uint32_t checksum_crc = crc32(cc->message[cc->block_index], CHECKSUM_OFFSET);
    if (strncmp(cc->message[cc->block_index] + (CHECKSUM_OFFSET), &checksum_crc, CHECKSUM_SIZE / 8) == 0) {
        printf("BLOCK VALIDATED\n");
        printf("received message:%s\n", cc->message[cc->block_index]);
        cc->block_index++;
        printf("Block index: %d\n", cc->block_index);
        if (cc->block_index >= cc->block_len) {
            cc->done = 1;
        }
        return;
    }

    // printf("Digest: ");
    // for (int i = 0; i < digest_len; i++) {
    //     printf("%02x", digest[i]);
    // }
    // // print received bits
    // printf("\n");
    // printf("Bit index: %d, Key bit: %d, Plain text bit: %d, Cipher text bit: %d, TSVAL: %u\n", bit_index, key_bit,
    //        plain_text_bit, cipher_text_bit, ntohl(*tsval));
    printf("current message:%s\n", cc->message[cc->block_index]);
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
        printf("RECEIVED MESSAGE\n");
        print_message_blocks(cc);
    }
    // print_packet(buffer, packet_size, "eth0", 0);
}

int main(int argc, char *argv[]) {

    char *dev = "eth0";
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    const char *secret_key = getenv("SECRET_KEY");
    cc = init_covert_channel(secret_key, 32);
    cc->message = malloc(EXPECTED_BLOCKS * sizeof(unsigned char *));
    for (int i = 0; i < EXPECTED_BLOCKS; i++) {
        cc->message[i] = malloc(BLOCKSIZE / 8);
        memset(cc->message[i], 0, BLOCKSIZE / 8);
    }
    cc->block_len = 27;

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
