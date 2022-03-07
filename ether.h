#ifndef ETHER_H_
#define ETHER_H_

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "net.h"

#define ETHER_ADDR_LEN         6
#define ETHER_ADDR_STR_LEN     18
#define ETHER_HDR_SIZE         14
#define ETHER_FRAME_SIZE_MIN   64
#define ETHER_FRAME_SIZE_MAX   1514
#define ETHER_PAYLOAD_SIZE_MIN 46
#define ETHER_PAYLOAD_SIZE_MAX 1500

// proto type for functions
typedef ssize_t (*ether_transmit_func_t)(struct net_device* dev,
                                         const uint8_t* data,
                                         size_t len);
typedef ssize_t (*ether_input_func_t)(struct net_device* dev,
                                      uint8_t* buf,
                                      size_t len);

// utils
char* ether_addr_ntop(const uint8_t* n, char* p, size_t size);
int ether_addr_pton(const char* p, uint8_t* n);

// common helper function to transmit/input/setup
int ether_transmit_helper(struct net_device* dev,
                          uint16_t type,
                          const uint8_t* data,
                          size_t len,
                          const void* dst,
                          ether_transmit_func_t callback);
int ether_input_helper(struct net_device* dev, ether_input_func_t callback);
void ether_setup_helper(struct net_device* dev);

extern const uint8_t ETHER_ADDR_ANY[ETHER_ADDR_LEN];
extern const uint8_t ETHER_ADDR_BROADCAST[ETHER_ADDR_LEN];

#endif  // ETHER_H_
