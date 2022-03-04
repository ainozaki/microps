#ifndef IP_H
#define IP_H

#include <stddef.h>
#include <stdint.h>

#include "net.h"

typedef uint32_t ip_addr_t;

struct ip_iface {
  struct net_iface iface;
  struct ip_iface* next;
  ip_addr_t unicast;
  ip_addr_t netmask;
  ip_addr_t broadcast;
};

int ip_init(void);

int ip_addr_pton(const char* p, ip_addr_t* n);
char* ip_addr_ntop(ip_addr_t n, char* p, size_t size);

void ip_dump(const uint8_t* data, size_t len);
#endif
