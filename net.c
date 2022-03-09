#include "net.h"

#include <signal.h>
#include <stddef.h>
#include <string.h>

#include "arp.h"
#include "icmp.h"
#include "intr.h"
#include "ip.h"
#include "platform.h"
#include "udp.h"
#include "util.h"

#define PROTOCOL_QUEUE_LIMIT

static struct net_device* devices;
static struct net_event* events;
static struct net_timer* timers;
static struct net_protocol* protocols;

struct net_protocol {
  struct net_protocol* next;
  uint16_t type;
  struct queue_head queue;
  void (*handler)(const uint8_t* data, size_t len, struct net_device* dev);
};

struct net_protocol_queue_entry {
  struct net_device* dev;
  size_t len;
  uint8_t data[];
};

struct net_timer {
  struct net_timer* next;
  struct timeval interval;
  struct timeval last;
  void (*handler)(void);
};

struct net_device* net_device_alloc(void) {
  struct net_device* dev;

  dev = memory_alloc(sizeof(*dev));
  if (!dev) {
    errorf("memory_alloc() failutre!");
    return NULL;
  }
  return dev;
}

int net_device_register(struct net_device* dev) {
  static unsigned int index = 0;

  dev->index = index++;
  snprintf(dev->name, sizeof(dev->name), "net%d", dev->index);
  dev->next = devices;
  devices = dev;
  infof("registered, dev=%s, type=0x%04x", dev->name, dev->type);
  return 0;
}

static int net_device_open(struct net_device* dev) {
  if (NET_DEVICE_IS_UP(dev)) {
    errorf("already opened, dev=%s", dev->name);
    return -1;
  }
  if (dev->ops->open) {
    if (dev->ops->open(dev) == -1) {
      errorf("failure opening, dev=%s", dev->name);
      return -1;
    }
  }
  dev->flags |= NET_DEVICE_FLAG_UP;
  infof("dev=%s, state=%s", dev->name, NET_DEVICE_STATE(dev));
  return 0;
}

static int net_device_close(struct net_device* dev) {
  if (!NET_DEVICE_IS_UP(dev)) {
    errorf("not opened, dev=%s", dev->name);
    return -1;
  }
  if (dev->ops->close) {
    if (dev->ops->close(dev) == -1) {
      errorf("failure closing, dev=%s", dev->name);
      return -1;
    }
  }
  dev->flags &= ~NET_DEVICE_FLAG_UP;
  infof("dev=%s, state=%s", dev->name, NET_DEVICE_STATE(dev));
  return 0;
}

int net_device_output(struct net_device* dev,
                      uint16_t type,
                      const uint8_t* data,
                      size_t len,
                      const void* dst) {
  if (!NET_DEVICE_IS_UP(dev)) {
    errorf("not opened, dev=%s", dev->name);
    return -1;
  }
  if (len > dev->mtu) {
    errorf("too long, dev=%s, mtu=%u, len=%zu", dev->name, dev->mtu, len);
    return -1;
  }
  debugf("dev=%s, type=0x%04x, len=%zu", dev->name, type, len);
  debugdump(data, len);
  if (dev->ops->transmit(dev, type, data, len, dst) == -1) {
    errorf("device transmit failure, dev=%s, len=%zu", dev->name, len);
    return -1;
  }
  return 0;
}

int net_input_handler(uint16_t type,
                      const uint8_t* data,
                      size_t len,
                      struct net_device* dev) {
  struct net_protocol* proto;

  for (proto = protocols; proto; proto = proto->next) {
    if (proto->type == type) {
      struct net_protocol_queue_entry* entry;
      unsigned int num;

      entry = memory_alloc(sizeof(*entry) + len);
      if (!entry) {
        errorf("memory_alloc() failure");
        return -1;
      }

      entry->dev = dev;
      entry->len = len;
      memcpy(entry->data, data, len);
      queue_push(&proto->queue, entry);
      num = proto->queue.num;
      debugf("queue pushed (num:%u), dev=%s, type=0x%04x, len=%zd", num,
             dev->name, proto->queue.num, dev->name, type, len);
      // software intr
      intr_raise_irq(INTR_IRQ_SOFTIRQ);
      return 0;
    }
  }

  // Unknown protocol
  return 0;
}

int net_run(void) {
  struct net_device* dev;
  if (intr_run() == -1) {
    errorf("intr_run failed");
    return -1;
  }

  debugf("open all devices...");
  for (dev = devices; dev; dev = dev->next) {
    net_device_open(dev);
  }
  debugf("running...");
  return 0;
}

int net_shutdown(void) {
  struct net_device* dev;
  intr_shutdown();
  debugf("close all devices...");
  for (dev = devices; dev; dev = dev->next) {
    net_device_close(dev);
  }
  debugf("shutting down");
  return 0;
}

int net_init(void) {
  if (intr_init() == -1) {
    errorf("intr_run failed");
    return -1;
  }

  if (ip_init() == -1) {
    errorf("ip_init failed");
    return -1;
  }

  if (arp_init() == -1) {
    errorf("arp_init failed");
    return -1;
  }

  if (icmp_init() == -1) {
    errorf("icmp_init failed");
    return -1;
  }

  if (udp_init() == -1) {
    errorf("icmp_init failed");
    return -1;
  }

  infof("initialized");
  return 0;
}

int net_protocol_register(uint16_t type,
                          void (*handler)(const uint8_t* data,
                                          size_t len,
                                          struct net_device* dev)) {
  struct net_protocol* proto;

  for (proto = protocols; proto; proto = proto->next) {
    if (type == proto->type) {
      errorf("net_protocol_register() failed, alreadt registered type=0x%04x",
             type);
      return -1;
    }
  }

  proto = memory_alloc(sizeof(*proto));
  if (!proto) {
    errorf("memory_alloc failed");
    return -1;
  }

  proto->type = type;
  proto->handler = handler;
  proto->next = protocols;
  protocols = proto;

  infof("registered, type=0x%04x", type);
  return 0;
}

int net_softirq_handler(void) {
  struct net_protocol* proto;
  struct net_protocol_queue_entry* entry;

  for (proto = protocols; proto; proto = proto->next) {
    while (1) {
      entry = queue_pop(&proto->queue);
      if (!entry) {
        break;
      }
      debugf("queue poped (num%u), dev=%s, type=0x%04x, len=%zu",
             proto->queue.num, entry->dev->name, proto->type, entry->len);
      // Call protocol interface func
      proto->handler(entry->data, entry->len, entry->dev);

      memory_free(entry);
    }
  }
  return 0;
}

int net_device_add_iface(struct net_device* dev, struct net_iface* iface) {
  struct net_iface* entry;

  for (entry = dev->ifaces; entry; entry = entry->next) {
    if (entry->family == iface->family) {
      // only one iface per family
      errorf("already exists, dev=%s, family=%d", dev->name, entry->family);
      return -1;
    }
  }
  iface->dev = dev;

  // add entry to device's interface list
  iface->next = dev->ifaces;
  dev->ifaces = iface;

  return 0;
}

struct net_iface* net_device_get_iface(struct net_device* dev, int family) {
  struct net_iface* entry;

  for (entry = dev->ifaces; entry; entry = entry->next) {
    if (entry->family == family) {
      return entry;
    }
  }
  return NULL;
}

int net_timer_register(struct timeval interval, void (*handler)(void)) {
  struct net_timer* entry;
  entry = memory_alloc(sizeof(*entry));
  if (!entry) {
    errorf("memory_alloc() failutre!");
    return -1;
  }

  entry->interval = interval;
  if (gettimeofday(&entry->last, NULL) < 0) {
    errorf("gettimeofday failed");
    return -1;
  }
  entry->handler = handler;

  entry->next = timers;
  timers = entry;
  infof("registered: interval={%d, %d}", interval.tv_sec, interval.tv_usec);
  return 0;
}

int net_timer_handler() {
  struct net_timer* timer;
  struct timeval now, diff;

  for (timer = timers; timer; timer = timer->next) {
    gettimeofday(&now, NULL);
    timersub(&now, &timer->last, &diff);
    if (timercmp(&timer->interval, &diff, <) != 0) {
      timer->handler();
      if (gettimeofday(&timer->last, NULL) < 0) {
        errorf("gettimeofday failed");
        return -1;
      }
    }
  }
  return 0;
}

/* net_event */
int net_event_subscribe(void (*handler)(void* arg), void* arg) {
  struct net_event* event;
  event = memory_alloc(sizeof(*event));
  if (!event) {
    errorf("memory_alloc() failure");
    return -1;
  }
  event->handler = handler;
  event->arg = arg;
  event->next = events;
  events = event;
  return 0;
}

int net_event_handler(void) {
  struct net_event* event;
  for (event = events; event; event = event->next) {
    event->handler(event->arg);
  }
  return 0;
}

void net_raise_event() {
  intr_raise_irq(INTR_IRQ_EVENT);
}
