#include "ip.h"

#include <stddef.h>
#include <stdlib.h>

#include "net.h"
#include "platform.h"
#include "util.h"

#define IP_ADDR_STR_LEN 16
#define IP_HDR_SIZE_MIN 20

#define IP_VERSION_4 4

#define IP_ADDR_BROADCAST 0xffffffff

static struct ip_iface* ifaces;

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
    errorf("Data length is too short.");
    return;
  }

  // checksum
  if (cksum16((uint16_t*)data, len, 0)) {
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

  ip_dump(data, total);
  debugf("dev=%s, iface=%s, len=%zu", dev->name,
         ip_addr_ntop(iface->unicast, addr, sizeof(addr)), len);
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
  fprintf(stderr, "        sum: 0x%04x\n", ntoh16(hdr->sum));
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
