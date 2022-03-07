#ifndef ARP_H_
#define ARP_H_

#include "ip.h"

#define ARP_RESOLVE_ERROR      -1
#define ARP_RESOLVE_INCOMPLETE 0
#define ARP_RESOLVE_FOUND      1

int arp_init();

int arp_resolve(struct net_iface* iface, ip_addr_t pa, uint8_t* ha);

#endif
