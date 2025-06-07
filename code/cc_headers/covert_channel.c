#include "covert_channel.h"
#include "aux.h"
#include <arpa/inet.h>
#include <inttypes.h>
#include <linux/if_ether.h>
#include <nats/nats.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netpacket/packet.h>
#include <openssl/hmac.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

uint32_t *get_tcp_timestamp(struct tcphdr *tcph) {
    int i;
    unsigned int tcp_header_len;
    unsigned int options_len;
    unsigned char *options;
    unsigned char kind;
    unsigned int option_len;
    uint32_t *tsval;

    if (tcph->doff <= 5)
        return NULL;

    options = (unsigned char *)tcph + 20;
    tcp_header_len = (unsigned int)tcph->doff * 4;
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
            if (i + 1 >= options_len)
                break;
            option_len = options[i + 1];
            if (kind == TCPOPT_TIMESTAMP && option_len == 10) {
                tsval = (uint32_t *)(options + i + 2);
                return tsval;
            }
            i += option_len;
        }
    }
    return NULL;
}

unsigned char get_key_bit(unsigned char *digest, unsigned int digest_len) {
    // get 9th bit of the digest
    return (digest[1]) & 0x01;
}
unsigned char get_bit_index(unsigned char *digest, unsigned int digest_len) {
    return digest[0];
}

int is_block_transmitted(struct covert_channel *cc) {
    // count 0s in transmit_count
    int count = 0;
    for (int i = 0; i < BLOCKSIZE; i++) {
        if (cc->transmit_count[i] < cc->occupation) {
            count++;
        }
    }
    printf("\r\033[KUnsent bit count(< OCCUPATION): %d", count);
    fflush(stdout);
    for (int i = 0; i < BLOCKSIZE; i++) {
        if (cc->transmit_count[i] < cc->occupation) {
            return 0;
        }
    }
    return 1;
}
unsigned char lsb(uint32_t x) {
    return (x) & 0x01;
}
void encode_packet(struct covert_channel *cc, unsigned char *const buffer) {
    struct iphdr *iph = (struct iphdr *)(buffer + sizeof(struct ethhdr));
    struct tcphdr *tcph = (struct tcphdr *)(buffer + iph->ihl * 4 + sizeof(struct ethhdr));
    unsigned char bit_index;
    unsigned char key_bit;
    unsigned char plain_text_bit;
    unsigned char cipher_text_bit;
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;
    unsigned short checksum;
    uint32_t *tsval;
    uint32_t tsval_val;

    HMAC(EVP_sha256(), cc->shared_key, sizeof(cc->shared_key), (unsigned char *)tcph, sizeof(struct tcphdr), digest,
         &digest_len);
    bit_index = get_bit_index(digest, digest_len);
    key_bit = get_key_bit(digest, digest_len);
    plain_text_bit = cc->message[bit_index / 8] >> (7 - (bit_index % 8)) & 0x01;
    cipher_text_bit = (key_bit ^ plain_text_bit);
    tsval = get_tcp_timestamp(tcph);

    // print digest
    // printf("DIGEST: ");
    // for (int i = 0; i < digest_len; i++) {
    //     printf("%02x", digest[i]);
    // }
    // printf("\n");
    // printf("Bit index: %d, Key bit: %d, Plain text bit: %d, Cipher text bit: %d, TSVAL: %u\n", bit_index, key_bit,
    //        plain_text_bit, cipher_text_bit, ntohl(*tsval));
    //
    // compare last bit of tsval with cipher_text_bit
    if (tsval != NULL) {
        tsval_val = ntohl(*tsval);
        // printf("TSVAL before :%u\n", tsval_val);
        if (lsb(tsval_val) != cipher_text_bit) {
            tsval_val++;
            *tsval = htonl(tsval_val);
            // printf("TSVAL after :%u\n", ntohl(*get_tcp_timestamp(tcph)));
            checksum = compute_tcp_checksum(buffer);
            tcph->check = checksum;
            encode_packet(cc, buffer);
            return;
        }
        cc->transmit_count[bit_index]++;
        if (is_block_transmitted(cc)) {
            printf("BLOCK TRANSMITTED\n");
            cc->done = 1;
        }
    }
    else {
        printf("No timestamp option found\n");
    }
}
void decode_packet(struct covert_channel *cc, unsigned char *const buffer) {
    struct iphdr *iph = (struct iphdr *)(buffer + sizeof(struct ethhdr));
    struct tcphdr *tcph = (struct tcphdr *)(buffer + iph->ihl * 4 + sizeof(struct ethhdr));

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
    // print received bits
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
        // printf("BLOCK RECEIVED in %d packets\n", packet_count);
        printf("received message: ");
        for (int i = 0; i < BLOCKSIZE / 8 - CHECKSUM_SIZE / 8; i++) {
            printf("%c", cc->message[i]);
        }
        printf("\n");
        cc->done = 1;
    }
}
uint32_t crc32(const unsigned char *data, size_t length) {
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < length; i++) {
        crc ^= data[i];
        for (int j = 0; j < 8; j++) {
            int mask = -(crc & 1);
            crc = (crc >> 1) ^ (0xEDB88320 & mask);
        }
    }
    return ~crc;
}
int init_message_from_file(struct covert_channel *cc, char *filename) {
    FILE *fp = fopen(filename, "r");
    int file_size;
    if (fp == NULL) {
        fprintf(stderr, "Error  message opening file\n");
        return 0;
    }
    // read contents of file into buffer
    fseek(fp, 0, SEEK_END);
    file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    fread(cc->message, 1, BLOCKSIZE / 8 - CHECKSUM_SIZE / 8, fp);
    cc->message_len = BLOCKSIZE / 8;
    return file_size;
}
void append_crc(struct covert_channel *cc) {
    uint32_t crc = crc32(cc->message, BLOCKSIZE / 8 - CHECKSUM_SIZE / 8);
    memcpy(cc->message + (BLOCKSIZE - CHECKSUM_SIZE) / 8, &crc, CHECKSUM_SIZE / 8);
    printf("message: ");
    for (int i = 0; i < BLOCKSIZE / 8 - CHECKSUM_SIZE / 8; i++) {
        printf("%c", cc->message[i]);
    }
    printf("\n");
    printf("crc: 0x%08X\n", *((uint32_t *)(cc->message + (BLOCKSIZE - CHECKSUM_SIZE) / 8)));
}
struct covert_channel *init_covert_channel(const char *shared_key, int key_len, int occupation) {
    struct covert_channel *cc = malloc(sizeof(struct covert_channel));
    hex_to_bytes(shared_key, cc->shared_key, key_len);
    memset(cc->transmit_count, 0, sizeof(cc->transmit_count));
    memset(cc->message, 0, sizeof(cc->message));

    cc->key_len = key_len;
    cc->done = 0;
    cc->occupation = occupation;
    return cc;
}
