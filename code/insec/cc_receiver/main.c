#include "../../c-processor/aux.h"
#include "../../c-processor/covert_channel.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <openssl/sha.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BLOCKSIZE 256    // Size of the message block in bits
#define CHECKSUM_SIZE 32 // Size of the checksum in bits

struct covert_channel cc;

// Function prototypes
int compute_bit_index(const unsigned char *packet_data, int packet_len);
int compute_key_bit(const unsigned char *packet_data, int packet_len);
void extract_bit_from_timestamp(const unsigned char *packet_data,
                                int packet_len);
void verify_message();
void packet_handler(u_char *user, const struct pcap_pkthdr *h,
                    const u_char *bytes);

int main(int argc, char **argv) {
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *handle;
  struct bpf_program fp;
  char filter_exp[] = "tcp"; // Only capture TCP packets
  bpf_u_int32 net, mask;

  if (argc != 3) {
    fprintf(stderr, "Usage: %s <interface> <shared_key>\n", argv[0]);
    exit(EXIT_FAILURE);
  }

  // Initialize the covert channel with the shared key
  init_covert_channel(argv[2], strlen(argv[2]));

  // Get network interface properties
  if (pcap_lookupnet(argv[1], &net, &mask, errbuf) == -1) {
    fprintf(stderr, "Can't get netmask for device %s: %s\n", argv[1], errbuf);
    net = 0;
    mask = 0;
  }

  // Open the network interface for capturing
  handle = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "Couldn't open device %s: %s\n", argv[1], errbuf);
    exit(EXIT_FAILURE);
  }

  // Compile and apply the filter
  if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
    fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp,
            pcap_geterr(handle));
    exit(EXIT_FAILURE);
  }

  if (pcap_setfilter(handle, &fp) == -1) {
    fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp,
            pcap_geterr(handle));
    exit(EXIT_FAILURE);
  }

  printf("Listening for covert data on %s...\n", argv[1]);

  // Start capturing packets
  pcap_loop(handle, -1, packet_handler, NULL);

  // Cleanup
  pcap_freecode(&fp);
  pcap_close(handle);

  return 0;
}

// Compute the index of the bit based on packet headers
int compute_bit_index(const unsigned char *packet_data, int packet_len) {
  unsigned char hash[SHA_DIGEST_LENGTH];
  SHA_CTX sha_ctx;

  SHA1_Init(&sha_ctx);
  SHA1_Update(&sha_ctx, packet_data, packet_len);
  SHA1_Update(&sha_ctx, channel.shared_key, channel.key_len);
  SHA1_Final(hash, &sha_ctx);

  // Use the last 10 bits of the hash to determine the bit index (for
  // BLOCKSIZE=1024)
  unsigned int index =
      ((hash[SHA_DIGEST_LENGTH - 2] << 8) | hash[SHA_DIGEST_LENGTH - 1]) &
      0x03FF;

  return index;
}

// Compute the key bit based on packet headers
int compute_key_bit(const unsigned char *packet_data, int packet_len) {
  unsigned char hash[SHA_DIGEST_LENGTH];
  SHA_CTX sha_ctx;

  SHA1_Init(&sha_ctx);
  SHA1_Update(&sha_ctx, packet_data, packet_len);
  SHA1_Update(&sha_ctx, channel.shared_key, channel.key_len);
  SHA1_Final(hash, &sha_ctx);

  // Use the 9th bit of the hash as the key bit
  return (hash[1] & 0x01);
}

// Set a specific bit in the message block
void set_message_bit(int index, int bit_value) {
  int byte_index = index / 8;
  int bit_offset = index % 8;

  if (bit_value) {
    channel.message_block[byte_index] |= (1 << (7 - bit_offset));
  } else {
    channel.message_block[byte_index] &= ~(1 << (7 - bit_offset));
  }

  channel.received_bits[index] = 1;
}

// Extract the covert bit from the timestamp and add it to the message
void extract_bit_from_timestamp(const unsigned char *packet_data,
                                int packet_len) {
  struct ip *ip_header = (struct ip *)packet_data;

  // Calculate IP header length
  int ip_header_len = ip_header->ip_hl * 4;

  // Get TCP header
  struct tcphdr *tcp_header = (struct tcphdr *)(packet_data + ip_header_len);

  // Calculate TCP header length
  int tcp_header_len = tcp_header->th_off * 4;

  // Check if there's room for TCP options
  if (tcp_header_len <= 20) {
    return; // No options
  }

  // Look for timestamp option (kind=8, length=10)
  unsigned char *options = (unsigned char *)tcp_header + 20;
  int options_len = tcp_header_len - 20;
  int i = 0;

  while (i < options_len) {
    unsigned char kind = options[i];

    if (kind == 0) {
      // End of options
      break;
    }

    if (kind == 1) {
      // NOP option
      i++;
      continue;
    }

    if (i + 1 >= options_len) {
      break; // Malformed options
    }

    unsigned char option_len = options[i + 1];

    if (option_len < 2 || i + option_len > options_len) {
      break; // Malformed option
    }

    if (kind == 8 && option_len == 10) {
      // Found timestamp option
      unsigned int ts_val = ntohl(*(unsigned int *)(options + i + 2));

      // Extract the low bit of the timestamp
      int cipher_bit = ts_val & 0x01;

      // Calculate the bit index using the packet headers as nonce
      int bit_index = compute_bit_index(packet_data, packet_len);

      // Compute the key bit
      int key_bit = compute_key_bit(packet_data, packet_len);

      // XOR the cipher bit with key bit to get the plaintext bit
      int plaintext_bit = cipher_bit ^ key_bit;

      // Set this bit in our message block
      set_message_bit(bit_index, plaintext_bit);

      printf("Received bit %d (value: %d)\n", bit_index, plaintext_bit);

      // Check if we've received a complete message
      verify_message();

      break;
    }

    i += option_len;
  }
}

// Check if the message is complete and valid
void verify_message() {
  int data_bits = BLOCKSIZE - CHECKSUM_SIZE;
  int complete = 1;

  // Check if we've received all data bits
  for (int i = 0; i < data_bits; i++) {
    if (!channel.received_bits[i]) {
      complete = 0;
      break;
    }
  }

  if (complete && !channel.message_complete) {
    // TODO: Verify checksum

    // For now, just print the message
    printf("Message complete! Content: ");

    // Print the message (ASCII bytes)
    for (int i = 0; i < data_bits / 8; i++) {
      // Stop at null byte or end of data
      if (channel.message_block[i] == 0) {
        break;
      }
      printf("%c", channel.message_block[i]);
    }
    printf("\n");

    channel.message_complete = 1;
  }
}

// Process each captured packet
void packet_handler(u_char *user, const struct pcap_pkthdr *h,
                    const u_char *bytes) {
  // Skip Ethernet header
  const u_char *packet = bytes + 14;

  struct ip *ip_header = (struct ip *)packet;

  // Verify this is a TCP packet
  if (ip_header->ip_p == IPPROTO_TCP) {
    // Process the packet to extract the covert bit
    extract_bit_from_timestamp(packet, h->caplen - 14);
  }
}
