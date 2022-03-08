#include "ip.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "arp.h"
#include "net.h"
#include "platform.h"
#include "util.h"

#define IP_VERSION_4 4

#define IP_TOTAL_SIZE_MAX UINT16_MAX

static struct ip_iface* ifaces;
static struct ip_protocol* protocols;
static struct ip_route* routes;

struct ip_hdr {
  uint8_t vhl;
  uint8_t tos;
  uint16_t total;
  uint16_t id;
  uint16_t offset;
  uint8_t ttl;
  uint8_t protocol;
  uint16_t sum;
  ip_addr_t src;
  ip_addr_t dst;
  uint8_t options[];
};

struct ip_protocol {
  struct ip_protocol* next;
  uint8_t type;
  void (*handler)(const uint8_t* data,
                  size_t len,
                  ip_addr_t src,
                  ip_addr_t dst,
                  struct ip_iface* iface);
};

struct ip_route {
  struct ip_route* next;
  ip_addr_t network;
  ip_addr_t netmask;
  ip_addr_t nexthop;
  struct ip_iface* iface;
};

static struct ip_route* ip_route_add(ip_addr_t network,
                                     ip_addr_t netmask,
                                     ip_addr_t nexthop,
                                     struct ip_iface* iface) {
  struct ip_route* route;
  char addr1[IP_ADDR_STR_LEN];
  char addr2[IP_ADDR_STR_LEN];
  char addr3[IP_ADDR_STR_LEN];
  char addr4[IP_ADDR_STR_LEN];

  route = memory_alloc(sizeof(*route));
  if (!route) {
    errorf("memory_alloc() fail");
    return NULL;
  }

  route->network = network;
  route->netmask = netmask;
  route->nexthop = nexthop;
  route->iface = iface;

  route->next = routes;
  routes = route;

  infof("route added: network=%s, netmask=%s, nexthop=%s, iface=%s, dev=%s",
        ip_addr_ntop(route->network, addr1, sizeof(addr1)),
        ip_addr_ntop(route->netmask, addr2, sizeof(addr2)),
        ip_addr_ntop(route->nexthop, addr3, sizeof(addr3)),
        ip_addr_ntop(route->iface->unicast, addr4, sizeof(addr4)),
        NET_IFACE(iface)->dev->name);
  return route;
}

static struct ip_route* ip_route_lookup(ip_addr_t dst) {
  struct ip_route *route, *candidate = NULL;

  for (route = routes; route; route = route->next) {
    if ((dst & route->netmask) == route->network) {
      if (!candidate || ntoh32(candidate->netmask) < ntoh32(route->netmask)) {
        candidate = route;
      }
    }
  }
  return candidate;
}

struct ip_iface* ip_route_get_iface(ip_addr_t dst) {
  struct ip_route* route;
  route = ip_route_lookup(dst);
  if (!route) {
    return NULL;
  }
  return route->iface;
}

int ip_route_set_default_gateway(struct ip_iface* iface, const char* gateway) {
  ip_addr_t gw;

  if (ip_addr_pton(gateway, &gw) == -1) {
    errorf("ip_addr_pton() failure, addr=%s", gateway);
    return -1;
  }

  if (!ip_route_add(IP_ADDR_ANY, IP_ADDR_ANY, gw, iface)) {
    errorf("ip_addr_add() failure");
    return -1;
  }
  return 0;
}

static void ip_input(const uint8_t* data, size_t len, struct net_device* dev) {
  struct ip_hdr* hdr;
  uint16_t hlen;
  uint16_t total;
  uint16_t offset;
  struct ip_iface* iface;
  char addr[IP_ADDR_STR_LEN];

  if (len < IP_HDR_SIZE_MIN) {
    errorf("too short length.");
    return;
  }

  hdr = (struct ip_hdr*)data;
  // version check
  if ((hdr->vhl & 0xf0) >> 4 != IP_VERSION_4) {
    errorf("Unsupported ip version.");
    return;
  }

  // header length check
  hlen = (hdr->vhl & 0x0f) * 4;
  if (len < hlen) {
    errorf("Data length is too short.");
    return;
  }

  // total length check
  total = ntoh16(hdr->total);
  if (len < total) {
    errorf("Data length is too short. len:%d, total: %d", len, total);
    return;
  }

  // checksum
  if (cksum16((uint16_t*)hdr, sizeof(struct ip_hdr), 0)) {
    errorf("Invalid checksum");
    return;
  }

  // Don't support fragmentation
  offset = ntoh16(hdr->offset);
  if (offset & 0x2000 || offset & 0x1fff) {
    errorf("Don't support fragments");
    return;
  }

  iface = (struct ip_iface*)net_device_get_iface(dev, NET_IFACE_FAMILY_IP);
  if (!iface) {
    errorf("get iface failure");
    return;
  }
  if (hdr->dst != iface->unicast && hdr->dst != iface->broadcast &&
      hdr->dst != IP_ADDR_BROADCAST) {
    // forwading
    return;
  }

  debugf("dev=%s, iface=%s, len=%zu", dev->name,
         ip_addr_ntop(iface->unicast, addr, sizeof(addr)), len);
  ip_dump(data, total);

  struct ip_protocol* entry;
  for (entry = protocols; entry; entry = entry->next) {
    if (entry->type == hdr->protocol) {
      return entry->handler((uint8_t*)hdr + hlen, total - hlen, hdr->src,
                            hdr->dst, iface);
    }
  }
  // Unsupported protocol
  return;
}

int ip_init(void) {
  if (net_protocol_register(NET_PROTOCOL_TYPE_IP, ip_input) == -1) {
    errorf("net_protocol_register() in ip failed.");
    return -1;
  }
  return 0;
}

int ip_addr_pton(const char* p, ip_addr_t* n) {
  char *sp, *ep;
  int idx;
  long ret;

  sp = (char*)p;
  for (idx = 0; idx < 4; idx++) {
    ret = strtol(sp, &ep, 10);
    if (ret < 0 || ret > 255) {
      return -1;
    }
    if (ep == sp) {
      return -1;
    }
    if ((idx == 3 && *ep != '\0') || (idx != 3 && *ep != '.')) {
      return -1;
    }
    ((uint8_t*)n)[idx] = ret;
    sp = ep + 1;
  }
  return 0;
}

char* ip_addr_ntop(ip_addr_t n, char* p, size_t size) {
  uint8_t* u8;

  u8 = (uint8_t*)&n;
  snprintf(p, size, "%d.%d.%d.%d", u8[0], u8[1], u8[2], u8[3]);
  return p;
}

void ip_dump(const uint8_t* data, size_t len) {
  struct ip_hdr* hdr;
  uint8_t v;
  uint8_t hl;
  uint8_t hlen;
  uint16_t total;
  uint16_t offset;
  char addr[IP_ADDR_STR_LEN];

  flockfile(stderr);
  hdr = (struct ip_hdr*)data;

  v = (hdr->vhl & 0xf0) >> 4;
  hl = hdr->vhl & 0x0f;
  hlen = hl << 2;
  total = ntoh16(hdr->total);
  offset = ntoh16(hdr->offset);

  fprintf(stderr, "      	 vhl: 0x%02x [v:%u, hl:%u (%u)]\n", hdr->vhl, v,
          hl, hlen);
  fprintf(stderr, "        tos: 0x%02x\n", hdr->tos);
  fprintf(stderr, "      total: %u(payload: %u)\n", total, total - hlen);
  fprintf(stderr, "         id: %u\n", ntoh16(hdr->id));
  fprintf(stderr, "     offset: 0x%04x [flags=%x, offset=%u]\n", offset,
          (offset & 0xe000) >> 13, offset & 0x1fff);
  fprintf(stderr, "        ttl: %u\n", hdr->ttl);
  fprintf(stderr, "   protocol: %u\n", hdr->protocol);
  fprintf(stderr, "        sum: 0x%04x, (0x%04x)\n", ntoh16(hdr->sum),
          ntoh16(cksum16((uint16_t*)data, hlen, -hdr->sum)));
  fprintf(stderr, "        src: %s\n",
          ip_addr_ntop(hdr->src, addr, sizeof(addr)));
  fprintf(stderr, "        dst: %s\n",
          ip_addr_ntop(hdr->dst, addr, sizeof(addr)));
  funlockfile(stderr);
}

struct ip_iface* ip_iface_alloc(const char* unicast, const char* netmask) {
  struct ip_iface* iface;

  iface = memory_alloc(sizeof(*iface));
  if (!iface) {
    errorf("memory_alloc() fail");
    return NULL;
  }

  NET_IFACE(iface)->family = NET_IFACE_FAMILY_IP;

  if (ip_addr_pton(unicast, &iface->unicast) < 0) {
    errorf("unicast pton failed");
    memory_free(iface);
  }

  if (ip_addr_pton(netmask, &iface->netmask) < 0) {
    errorf("netmask pton failed");
    memory_free(iface);
  }

  iface->broadcast = iface->unicast & iface->netmask;
  iface->broadcast |= ~(0xffffffff & iface->netmask);
  return iface;
}

int ip_iface_register(struct net_device* dev, struct ip_iface* iface) {
  char addr1[IP_ADDR_STR_LEN];
  char addr2[IP_ADDR_STR_LEN];
  char addr3[IP_ADDR_STR_LEN];

  // register iface to dev
  if (net_device_add_iface(dev, (struct net_iface*)iface) < 0) {
    errorf("failed to register iface to dev");
    return -1;
  }

  struct ip_route* route = ip_route_add(iface->unicast & iface->netmask,
                                        iface->netmask, IP_ADDR_ANY, iface);
  if (!route) {
    errorf("failed to add route");
    return -1;
  }

  // add iface to ifaces
  iface->next = ifaces;
  ifaces = iface;

  infof("registered: dev=%s, unicast=%s, netmask=%s, broadcast=%s", dev->name,
        ip_addr_ntop(iface->unicast, addr1, sizeof(addr1)),
        ip_addr_ntop(iface->netmask, addr2, sizeof(addr2)),
        ip_addr_ntop(iface->broadcast, addr3, sizeof(addr3)));
  return 0;
}

struct ip_iface* ip_iface_select(ip_addr_t addr) {
  struct ip_iface* entry;
  for (entry = ifaces; entry; entry = entry->next) {
    if (entry->unicast == addr) {
      return entry;
    }
  }
  return NULL;
}

static uint16_t ip_generate_id(void) {
  static mutex_t mutex = MUTEX_INITIALIZER;
  static uint16_t id = 128;
  uint16_t ret;
  mutex_lock(&mutex);
  ret = id++;
  mutex_unlock(&mutex);
  return ret;
}

static int ip_output_device(struct ip_iface* iface,
                            const uint8_t* data,
                            size_t len,
                            ip_addr_t dst) {
  uint8_t hwaddr[NET_DEVICE_ADDR_LEN];

  if (NET_IFACE(iface)->dev->flags & NET_DEVICE_FLAG_NEED_ARP) {
    if (dst == iface->broadcast || dst == IP_ADDR_BROADCAST) {
      memcpy(hwaddr, NET_IFACE(iface)->dev->broadcast,
             NET_IFACE(iface)->dev->alen);
    } else {
      int arp_result = arp_resolve(NET_IFACE(iface), dst, hwaddr);
      if (arp_result != ARP_RESOLVE_FOUND) {
        debugf("cannot arp resolve found");
        return arp_result;
      }
      debugf("arp resolved");
    }
  }
  return net_device_output(NET_IFACE(iface)->dev, NET_PROTOCOL_TYPE_IP, data,
                           len, hwaddr);
}

static ssize_t ip_output_core(struct ip_iface* iface,
                              uint8_t protocol,
                              const uint8_t* data,
                              size_t len,
                              ip_addr_t src,
                              ip_addr_t dst,
                              ip_addr_t nexthop,
                              uint16_t id,
                              uint16_t offset) {
  uint8_t buf[IP_TOTAL_SIZE_MAX];
  struct ip_hdr* hdr;
  uint16_t total, hlen;
  char addr[IP_ADDR_STR_LEN];

  hlen = sizeof(*hdr);
  hdr = (struct ip_hdr*)buf;
  hdr->vhl = (0x04 << 4) | (hlen >> 2);
  hdr->tos = 0;
  total = hlen + len;
  hdr->total = hton16(total);
  hdr->id = hton16(id);
  hdr->offset = 0;
  hdr->ttl = 255;
  hdr->protocol = protocol;
  hdr->sum = 0;
  hdr->src = src;
  hdr->dst = dst;
  hdr->sum = cksum16((uint16_t*)hdr, hlen, 0);

  memcpy(buf + IP_HDR_SIZE_MIN, data, len);

  debugf("dev=%s, dst=%s, protocol=%u, len=%u", NET_IFACE(iface)->dev->name,
         ip_addr_ntop(dst, addr, sizeof(addr)), protocol, total);
  ip_dump(buf, total);
  return ip_output_device(iface, buf, total, nexthop);
}

ssize_t ip_output(uint8_t protocol,
                  const uint8_t* data,
                  size_t len,
                  ip_addr_t src,
                  ip_addr_t dst) {
  struct ip_iface* iface;
  struct ip_route* route;
  ip_addr_t nexthop;
  char addr[IP_ADDR_STR_LEN];
  char addr2[IP_ADDR_STR_LEN];
  uint16_t id;

  if (src == IP_ADDR_ANY && dst == IP_ADDR_BROADCAST) {
    errorf("source address is required for broadcast");
    return -1;
  }
  route = ip_route_lookup(dst);
  if (!route) {
    errorf("no root to host, addr=%s", ip_addr_ntop(dst, addr, sizeof(addr)));
    return -1;
  }
  iface = route->iface;
  if (src != IP_ADDR_ANY && src != iface->unicast) {
    errorf(
        "unable to output with specified source address, addr=%s, "
        "iface->unicast=%s",
        ip_addr_ntop(src, addr, sizeof(addr)),
        ip_addr_ntop(iface->unicast, addr2, sizeof(addr2)));
    return -1;
  }

  nexthop = (route->nexthop != IP_ADDR_ANY) ? route->nexthop : dst;

  if (NET_IFACE(iface)->dev->mtu < IP_HDR_SIZE_MIN + len) {
    errorf("too long, dev=%s, mtu=%u < %zu", NET_IFACE(iface)->dev->name,
           NET_IFACE(iface)->dev->mtu, IP_HDR_SIZE_MIN + len);
    return -1;
  }

  id = ip_generate_id();
  if (ip_output_core(iface, protocol, data, len, iface->unicast, dst, nexthop,
                     id, 0) == -1) {
    errorf("ip_output_core() failure");
    return -1;
  }

  return len;
}

int ip_protocol_register(uint8_t type,
                         void (*handler)(const uint8_t* data,
                                         size_t len,
                                         ip_addr_t src,
                                         ip_addr_t dst,
                                         struct ip_iface* iface)) {
  struct ip_protocol* entry;

  for (entry = protocols; entry; entry = entry->next) {
    if (entry->type == type) {
      errorf("IP protocol type %d already exist", type);
      return -1;
    }
  }

  entry = (struct ip_protocol*)malloc(sizeof(struct ip_protocol));
  if (!entry) {
    errorf("error malloc struct ip_protocol");
    return -1;
  }
  entry->type = type;
  entry->handler = handler;
  entry->next = protocols;
  protocols = entry;

  infof("registerd type=%d", entry->type);
  return 0;
}

int ip_endpoint_pton(const char* p, struct ip_endpoint* n) {
  char* sep;
  char addr[IP_ADDR_STR_LEN] = {};
  long int port;

  sep = strrchr(p, ':');
  if (!sep) {
    return -1;
  }
  memcpy(addr, p, sep - p);
  if (ip_addr_pton(addr, &n->addr) == -1) {
    return -1;
  }
  port = strtol(sep + 1, NULL, 10);
  if (port <= 0 || port > UINT16_MAX) {
    return -1;
  }
  n->port = hton16(port);
  return 0;
}

char* ip_endpoint_ntop(const struct ip_endpoint* n, char* p, size_t size) {
  size_t offset;

  ip_addr_ntop(n->addr, p, size);
  offset = strlen(p);
  snprintf(p + offset, size - offset, ":%d", ntoh16(n->port));
  return p;
}
