#ifndef UDP_H_
#define UDP_H_

#include <stdint.h>

#include "ip.h"

struct pseudo_hdr {
  uint32_t src;
  uint32_t dst;
  uint8_t zero;
  uint8_t protocol;
  uint16_t len;
};

struct udp_hdr {
  uint16_t src;
  uint16_t dst;
  uint16_t len;
  uint16_t sum;
};

int udp_init();

ssize_t udp_output(struct ip_endpoint* src,
                   struct ip_endpoint* dst,
                   const uint8_t* data,
                   size_t len);

int udp_open();
int udp_close(int fd);

int udp_bind(int id, struct ip_endpoint* local);

ssize_t udp_sendto(int id,
                   uint8_t* data,
                   size_t len,
                   struct ip_endpoint* foreign);

ssize_t udp_recvfrom(int id,
                     uint8_t* buf,
                     size_t size,
                     struct ip_endpoint* foreign);

#endif
