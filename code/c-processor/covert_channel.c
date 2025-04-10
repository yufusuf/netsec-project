#include "covert_channel.h"
#include "aux.h"
#include <arpa/inet.h>
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
#include <stdlib.h>
#include <string.h>
// struct covert_channel
// {
//     unsigned char message[BLOCKSIZE / 8]; // Message to send
//     int message_len;                      // Length of message in bytes
//     int transmit_count[BLOCKSIZE];        // Track how many times each bit has been sent
//     unsigned char shared_key[32];         // Shared secret key
//     int key_len;                          // Length of the key
// };
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
        if (kind == 0)
            break; // End of option list
        else if (kind == 1) {
            i++;
            continue;
        } // NOP

        if (i + 1 >= options_len)
            break;

        option_len = options[i + 1];
        if (option_len < 2 || i + option_len > options_len)
            break;

        if (kind == TCPOPT_TIMESTAMP && option_len == 10) {
            tsval = (uint32_t *)&options[i + 2];
            return tsval;
        }

        i += option_len;
    }
    return NULL;
}

unsigned char get_key_bit(unsigned char *digest, unsigned int digest_len) {
    // get 9th bit of the digest
    return (digest[1] >> 7) & 0x01;
}
unsigned char get_bit_index(unsigned char *digest, unsigned int digest_len) {
    return digest[0];
}

int is_block_transmitted(struct covert_channel *cc) {
    // print values
    // for (int i = 0; i < BLOCKSIZE; i++) {
    //     printf("%d", cc->transmit_count[i]);
    // }
    // printf("\n");
    for (int i = 0; i < BLOCKSIZE; i++) {
        if (cc->transmit_count[i] < OCCUPATION) {
            return 0;
        }
    }
    return 1;
}
void encodePacket(struct covert_channel *cc, unsigned char *buffer) {
    struct ethhdr *eth = (struct ethhdr *)buffer;
    struct iphdr *iph = (struct iphdr *)(buffer + sizeof(struct ethhdr));
    struct tcphdr *tcph = (struct tcphdr *)(buffer + iph->ihl * 4 + sizeof(struct ethhdr));
    int tcp_header_len = (unsigned int)tcph->doff * 4;
    unsigned char bit_index;
    unsigned char key_bit;
    unsigned char plain_text_bit;
    unsigned char cipher_text_bit;
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;
    uint32_t *tsval;
    uint32_t tsval_val;

    HMAC(EVP_sha256(), cc->shared_key, sizeof(cc->shared_key), (unsigned char *)tcph, tcp_header_len, digest,
         &digest_len);
    bit_index = get_bit_index(digest, digest_len);
    key_bit = get_key_bit(digest, digest_len);
    plain_text_bit = cc->message[bit_index / 8] >> (7 - (bit_index % 8)) & 0x01;
    cipher_text_bit = (key_bit ^ plain_text_bit);
    tsval = get_tcp_timestamp(tcph);

    // printf("Bit index: %d, Key bit: %d, Plain text bit: %d, Cipher text bit: %d\n", bit_index, key_bit,
    // plain_text_bit,
    //        cipher_text_bit);
    // // print digest
    // printf("Digest: ");
    // for (int i = 0; i < digest_len; i++) {
    //     printf("%02x", digest[i]);
    // }
    // printf("\n");

    // compare last bit of tsval with cipher_text_bit
    if (tsval != NULL) {
        tsval_val = ntohs(*tsval);
        if ((tsval_val & 0x01) != cipher_text_bit) {
            tsval_val++;
            *tsval = htonl(tsval_val);
            if ((tsval_val & 0x01) == 0) {
                // printf("retrying...\n");
                encodePacket(cc, buffer);
            }
            cc->transmit_count[bit_index]++;
            if (is_block_transmitted(cc)) {
                printf("BLOCK TRANSMITTED\n");
                cc->done = 1;
            }
        }
    }
    else {
        printf("No timestamp option found\n");
    }
}
int read_message_from_file(char *filename, char *buffer) {
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
    fread(buffer, 1, BLOCKSIZE / 8, fp);
    return file_size;
}
struct covert_channel *init_covert_channel(const char *shared_key, int key_len) {
    struct covert_channel *cc = malloc(sizeof(struct covert_channel));
    char buff[BLOCKSIZE / 8] = {0};
    int msg_len = read_message_from_file("test.txt", buff);
    printf("Message : %s\n", buff);
    hex_to_bytes(shared_key, cc->shared_key, key_len);
    cc->message_len = msg_len;
    memcpy(cc->message, buff, msg_len);
    memset(cc->transmit_count, 0, sizeof(cc->transmit_count));
    cc->key_len = key_len;
    cc->done = 0;
    // print channel details

    return cc;
}
