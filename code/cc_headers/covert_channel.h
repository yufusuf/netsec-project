#ifndef COVERT_CHANNEL_H
#define COVERT_CHANNEL_H

#include <netinet/tcp.h>
#include <stdint.h>
#define BLOCKSIZE 256 // in bits
#define OCCUPATION 1
#define CHECKSUM_SIZE 32                                    // in bits
#define CHECKSUM_OFFSET (BLOCKSIZE / 8 - CHECKSUM_SIZE / 8) // in bytes
struct covert_channel
{
    unsigned char **message; //[BLOCKSIZE / 8]; // Message to send
    int block_len;           // Length of message in bytes
    int done;
    int block_index;
    int **transmit_count;         //[BLOCKSIZE]; // Track how many times each bit has been sent
    unsigned char shared_key[32]; // Shared secret key
    int key_len;                  // Length of the key
    int packet_count;
};
int init_message_from_file(struct covert_channel *cc, char *filename);
void encode_packet(struct covert_channel *cc, unsigned char *buffer);
uint32_t *get_tcp_timestamp(struct tcphdr *tcph);
int is_block_transmitted(struct covert_channel *cc);
unsigned char get_bit_index(unsigned char *digest, unsigned int digest_len);
unsigned char get_key_bit(unsigned char *digest, unsigned int digest_len);
struct covert_channel *init_covert_channel(const char *shared_key, int key_len);
unsigned char lsb(uint32_t x);
uint32_t crc32(const unsigned char *data, size_t length); // CRC-32/ISO-HDLC
void print_message_blocks(struct covert_channel *cc);
#endif // !COVERT_CHANNEL_H
