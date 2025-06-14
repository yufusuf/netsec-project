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
        if (cc->transmit_count[cc->block_index][i] < cc->occupation) {
            count++;
        }
    }
    printf("\r\033[KUnsent bit count(< OCCUPATION): %d", count);
    fflush(stdout);
    return count == 0;
    // for (int i = 0; i < BLOCKSIZE; i++) {
    //     if (cc->transmit_count[cc->block_index][i] < cc->occupation) {
    //         return 0;
    //     }
    // }
    // return 1;
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
    plain_text_bit = cc->message[cc->block_index][bit_index / 8] >> (7 - (bit_index % 8)) & 0x01;
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
        if (lsb(tsval_val) != cipher_text_bit) {
            tsval_val++;
            *tsval = htonl(tsval_val);
            checksum = compute_tcp_checksum(buffer);
            tcph->check = checksum;
            encode_packet(cc, buffer);
            return;
            // TODOL: if timestamp highber bits included in digest calculation in the future,
            //  check (lsb(tsval_val) == 0) if they are changed then call encode_packet again
        }
        cc->transmit_count[cc->block_index][bit_index]++;
        if (is_block_transmitted(cc)) {
            printf("BLOCK TRANSMITTED\n");
            cc->block_index++;
            if (cc->block_index >= cc->block_len) {
                cc->done = 1;
                printf("All blocks transmitted\n");
            }
            else {
                printf("Next block index: %d\n", cc->block_index);
                // next message
                printf("Next message: %.28s\n", cc->message[cc->block_index]);
            }
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

    bit_index = get_bit_index(digest, digest_len);
    key_bit = get_key_bit(digest, digest_len);
    tsval = get_tcp_timestamp(tcph);
    if (tsval == NULL) {
        printf("No timestamp option found\n");
        return;
    }
    cipher_text_bit = ntohl(*tsval) & 0x01;
    plain_text_bit = key_bit ^ cipher_text_bit;
    size_t byte_idx = bit_index / 8;
    uint8_t bit_pos = 7 - (bit_index % 8);
    uint8_t mask = (1u << bit_pos);
    cc->message[cc->block_index][byte_idx] =
        (cc->message[cc->block_index][byte_idx] & ~mask) | ((plain_text_bit << bit_pos) & mask);

    // printf("Digest: ");
    // for (int i = 0; i < digest_len; i++) {
    //     printf("%02x", digest[i]);
    // }
    // print received bits
    // printf("\n");
    // printf("Bit index: %d, Key bit: %d, Plain text bit: %d, Cipher text bit: %d, TSVAL: %u\n", bit_index, key_bit,
    //        plain_text_bit, cipher_text_bit, ntohl(*tsval));
    crc = crc32(cc->message[cc->block_index], CHECKSUM_OFFSET);
    // printf("\r\033[Kmessage:%.28s crc: 0x%08X\n", cc->message[cc->block_index], crc);
    // fflush(stdout);
    // validate crc
    if (crc != 0 &&
        (memcmp((uint32_t *)(cc->message[cc->block_index] + CHECKSUM_OFFSET), &crc, CHECKSUM_SIZE / 8) == 0)) {
        printf("received message: ");
        for (int i = 0; i < CHECKSUM_OFFSET; i++) {
            printf("%c", cc->message[cc->block_index][i]);
        }
        printf("\n");
        cc->block_index++;
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
void print_message_blocks(struct covert_channel *cc) {
    int chunk_size = BLOCKSIZE / 8;

    for (int i = 0; i < cc->block_len; i++) {
        printf("Block %d:\n", i);

        // Print the first 32 bytes of the message as a string
        printf("Message: ");
        for (int j = 0; j < chunk_size - CHECKSUM_SIZE / 8; j++) {
            printf("%c", cc->message[i][j]);
        }

        printf("\n");

        // Extract the checksum (first 4 bytes of CHECKSUM_SIZE)
        uint32_t checksum;
        memcpy(&checksum, cc->message[i] + CHECKSUM_OFFSET, sizeof(uint32_t));

        printf("\n  CRC32: 0x%08X\n", checksum);

        printf("\n\n");
    }
}
int init_message_from_file(struct covert_channel *cc, char *filename) {
    FILE *fp = fopen(filename, "rb");
    if (fp == NULL) {
        fprintf(stderr, "Error opening file\n");
        return 0;
    }

    fseek(fp, 0, SEEK_END);
    int file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    int chunk_size = BLOCKSIZE / 8;
    int msg_size = chunk_size - CHECKSUM_SIZE / 8;
    int total_blocks = (file_size + msg_size - 1) / chunk_size;

    cc->message = malloc(total_blocks * sizeof(unsigned char *));
    cc->transmit_count = malloc(total_blocks * sizeof(int *));

    for (int i = 0; i < total_blocks; i++) {
        cc->message[i] = malloc(chunk_size);
        cc->transmit_count[i] = calloc(BLOCKSIZE, sizeof(int));

        size_t read_bytes = fread(cc->message[i], 1, msg_size, fp);
        if (read_bytes < msg_size) {
            memset(cc->message[i] + read_bytes, 0, msg_size - read_bytes);
        }
        append_crc(cc, i);
    }

    fclose(fp);

    cc->block_len = total_blocks;
    // print_message_blocks(cc);

    return file_size;
}
void append_crc(struct covert_channel *cc, int i) {
    uint32_t crc = crc32(cc->message[i], CHECKSUM_OFFSET);
    memcpy(cc->message[i] + CHECKSUM_OFFSET, &crc, CHECKSUM_SIZE / 8);
    // printf("message: ");
    // for (int j = 0; j < CHECKSUM_OFFSET; j++) {
    //     printf("%c", cc->message[i][j]);
    // }
    // printf("\n");
    // printf("crc: 0x%08X\n", *((uint32_t *)(cc->message + CHECKSUM_OFFSET)));
}
struct covert_channel *init_covert_channel(const char *shared_key, int key_len, int occupation) {
    struct covert_channel *cc = malloc(sizeof(struct covert_channel));
    hex_to_bytes(shared_key, cc->shared_key, key_len);

    cc->key_len = key_len;
    cc->done = 0;
    cc->occupation = occupation;
    cc->block_index = 0;
    return cc;
}
