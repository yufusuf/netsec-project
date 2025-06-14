#ifndef COVERT_CHANNEL_H
#define COVERT_CHANNEL_H

#include <netinet/tcp.h>
#include <stdint.h>
#define BLOCKSIZE 256
#define CHECKSUM_SIZE 32
#define CHECKSUM_OFFSET (BLOCKSIZE / 8 - CHECKSUM_SIZE / 8)
struct covert_channel {
  unsigned char **message;      // Message to send
  unsigned char shared_key[32]; // Shared secret key
  int **transmit_count;         // Track how many times each bit has been sent
  int block_len;                // Number of blocks in the message
  int block_index;
  int message_len; // Length of message in bytes
  int done;
  int key_len;    // Length of the key
  int occupation; // Number of bits to transmit
};
int init_message_from_file(struct covert_channel *cc, char *filename);
void encode_packet(struct covert_channel *cc, unsigned char *const buffer);
void decode_packet(struct covert_channel *cc, unsigned char *const buffer);
uint32_t *get_tcp_timestamp(struct tcphdr *tcph);
int is_block_transmitted(struct covert_channel *cc);
unsigned char get_bit_index(unsigned char *digest, unsigned int digest_len);
unsigned char get_key_bit(unsigned char *digest, unsigned int digest_len);
struct covert_channel *init_covert_channel(const char *shared_key, int key_len,
                                           int occupation);
unsigned char lsb(uint32_t x);
uint32_t crc32(const unsigned char *data, size_t length);
void append_crc(struct covert_channel *cc, int i);
void print_message_blocks(struct covert_channel *cc);
#endif // !COVERT_CHANNEL_H
