#ifndef ETHER_TAP_H
#define ETHER_TAP_H

#include <stddef.h>
#include <stdint.h>
#include <unistd.h>

#include "net.h"

int ether_tap_transmit(struct net_device* dev,
                       uint16_t type,
                       const uint8_t* buf,
                       size_t len,
                       const void* dst);

struct net_device* ether_tap_init(const char* name, const char* addr);

#endif  // ETHER_TAP_H
