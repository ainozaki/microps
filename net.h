#ifndef NET_H_
#define NET_H_

#include <stddef.h>
#include <stdint.h>

#define NET_DEVICE_FLAG_UP       0x0001
#define NET_DEVICE_FLAG_LOOPBACK 0x0010

#define NET_DEVICE_ADDR_LEN 16
#define IFNAMSIZ            16

#define NET_DEVICE_IS_UP(x) ((x)->flags & NET_DEVICE_FLAG_UP)
#define NET_DEVICE_STATE(x) (NET_DEVICE_IS_UP(x) ? "up" : "down")

#define NET_DEVICE_TYPE_DUMMY    0x0000
#define NET_DEVICE_TYPE_LOOPBACK 0x0001

#define NET_PROTOCOL_TYPE_IP 0x0800

struct net_device {
  struct net_device* next;
  unsigned int index;
  char name[IFNAMSIZ];
  uint16_t type;
  uint16_t mtu;
  uint16_t flags;
  uint16_t hlen;
  uint16_t alen;
  uint8_t addr[NET_DEVICE_ADDR_LEN];
  union {
    uint8_t peer[NET_DEVICE_ADDR_LEN];
    uint8_t broadcast[NET_DEVICE_ADDR_LEN];
  };
  struct net_device_ops* ops;
  void* priv;
};

struct net_device_ops {
  int (*open)(struct net_device* dev);
  int (*close)(struct net_device* dev);
  int (*transmit)(struct net_device* dev,
                  uint16_t type,
                  const uint8_t* data,
                  size_t len,
                  const void* dst);
};

struct net_device* net_device_alloc(void);

int net_device_register(struct net_device* dev);

int net_device_output(struct net_device* dev,
                      uint16_t type,
                      const uint8_t* data,
                      size_t len,
                      const void* dst);

int net_input_handler(uint16_t type,
                      const uint8_t* data,
                      size_t len,
                      struct net_device* dev);

int net_run(void);
int net_shutdown(void);
int net_init(void);

// protocols
int net_protocol_register(uint16_t type,
                          void (*handler)(const uint8_t* data,
                                          size_t len,
                                          struct net_device* dev));
#endif
