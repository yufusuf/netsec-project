#ifndef AUX_H
#define AUX_H

#include <netinet/tcp.h>
void print_packet(unsigned char *buffer, int size, char *iface, int is_outgoing);
double get_expo_random(double lambda);
void hex_to_bytes(const char *hex, unsigned char *bytes, int len);
unsigned short compute_tcp_checksum(unsigned char *buffer);
#endif /* ifndef AUX_H */
