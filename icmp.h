#ifndef ICMP_H
#define ICMP_H

#include <stddef.h>

#include "ip.h"

#define ICMP_TYPE_ECHOREPLY      0x00
#define ICMP_TYPE_DEST_UNREACH   0x03
#define ICMP_TYPE_SOURCE_QUENCH  0x04
#define ICMP_TYPE_REDIRECT       0x5
#define ICMP_TYPE_ECHO           0x08
#define ICMP_TYPE_TIME_EXCEEDED  0x0b
#define ICMP_TYPE_PARAM_PROBLEM  0x0c
#define ICMP_TYPE_TIMESTAMP      0x0d
#define ICMP_TYPE_TIMESTAMPREPLY 0x0e
#define ICMP_TYPE_INFO_REQUEST   0x0f
#define ICMP_TYPE_INFO_REPLY     0x10

#define ICMP_HDR_SIZE 8

void icmp_input(const uint8_t* data,
                size_t len,
                ip_addr_t src,
                ip_addr_t dst,
                struct ip_iface* iface);

int icmp_output(uint8_t type,
                uint8_t code,
                uint32_t values,
                const uint8_t* data,
                size_t len,
                ip_addr_t src,
                ip_addr_t dst);

int icmp_init();

#endif  // ICMP_H
