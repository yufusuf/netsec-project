#ifndef COVERT_CHANNEL_H
#define COVERT_CHANNEL_H

#include <netinet/tcp.h>
#include <stdint.h>
#define BLOCKSIZE 256
#define OCCUPATION 1
#define CHECKSUM_SIZE 32
struct covert_channel
{
    unsigned char message[BLOCKSIZE / 8]; // Message to send
    int message_len;                      // Length of message in bytes
    int done;
    int transmit_count[BLOCKSIZE]; // Track how many times each bit has been sent
    unsigned char shared_key[32];  // Shared secret key
    int key_len;                   // Length of the key
};
int read_message_from_file(char *filename, char *buffer);
void encodePacket(struct covert_channel *cc, unsigned char *buffer);
uint32_t *get_tcp_timestamp(struct tcphdr *tcph);
int is_block_transmitted(struct covert_channel *cc);
unsigned char get_bit_index(unsigned char *digest, unsigned int digest_len);
unsigned char get_key_bit(unsigned char *digest, unsigned int digest_len);
struct covert_channel *init_covert_channel(const char *shared_key, int key_len);

#endif // !COVERT_CHANNEL_H
