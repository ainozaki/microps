#include "loopback.h"

#include <string.h>

#include "intr.h"
#include "net.h"
#include "platform.h"
#include "util.h"

#define LOOPBACK_IRQ         INTR_BASE + 1
#define LOOPBACK_MTU         1500
#define LOOPBACK_QUEUE_LIMIT 16

#define PRIV(x) ((struct loopback*)x->priv)

struct loopback_queue_entry {
  uint16_t type;
  size_t len;
  uint8_t data[];
};

struct loopback {
  int irq;
  mutex_t mutex;
  struct queue_head queue;
};

static int loopback_transmit(struct net_device* dev,
                             uint16_t type,
                             const uint8_t* data,
                             size_t len,
                             const void* dst) {
  struct loopback_queue_entry* entry;
  unsigned int num;

  mutex_lock(&PRIV(dev)->mutex);
  if (PRIV(dev)->queue.num >= LOOPBACK_QUEUE_LIMIT) {
    mutex_unlock(&PRIV(dev)->mutex);
    errorf("err: queue is full");
    return -1;
  }

  entry = memory_alloc(sizeof(*entry) + len);
  if (!entry) {
    mutex_unlock(&PRIV(dev)->mutex);
    errorf("memory_alloc() failure");
    return -1;
  }

  entry->type = type;
  entry->len = len;
  memcpy(entry->data, data, len);
  queue_push(&PRIV(dev)->queue, entry);
  num = PRIV(dev)->queue.num;
  mutex_unlock(&PRIV(dev)->mutex);

  debugf("queue pushed (num:%u), dev=%s, type=0x%04x, len=%zd", num, dev->name,
         type, len);
  debugdump(data, len);

  intr_raise_irq(PRIV(dev)->irq);
  return 0;
}

static struct net_device_ops loopback_ops = {
    .transmit = loopback_transmit,
};

static int loopback_isr(unsigned int irq, void* id) {
  struct net_device* dev;
  struct loopback_queue_entry* entry;

  dev = (struct net_device*)id;
  mutex_lock(&PRIV(dev)->mutex);
  while (1) {
    // Pop entry from queue
    entry = queue_pop(&PRIV(dev)->queue);
    if (!entry) {
      break;
    }
    debugf("queue poped (num: %u), dev=%s, type=0x%04x, len=%zd",
           PRIV(dev)->queue.num, dev->name, entry->type, entry->len);

    // Pass to protocol stack
    net_input_handler(entry->type, entry->data, entry->len, dev);
    memory_free(entry);
  }
  mutex_unlock(&PRIV(dev)->mutex);
  return 0;
}

struct net_device* loopback_init(void) {
  struct net_device* dev;
  struct loopback* lo;

  // Create device
  dev = net_device_alloc();
  if (!dev) {
    errorf("net_device_alloc() failure");
    return NULL;
  }
  dev->type = NET_DEVICE_TYPE_LOOPBACK;
  dev->mtu = LOOPBACK_MTU;
  dev->hlen = 0;
  dev->alen = 0;
  dev->ops = &loopback_ops;
  dev->flags = NET_DEVICE_FLAG_LOOPBACK;

  lo = memory_alloc(sizeof(*lo));
  if (!lo) {
    errorf("memory_alloc failer");
    return NULL;
  }
  lo->irq = LOOPBACK_IRQ;
  mutex_init(&lo->mutex);
  queue_init(&lo->queue);
  dev->priv = lo;

  // Register device
  if (net_device_register(dev) == -1) {
    errorf("net_device_register() failure");
    return NULL;
  }

  // Register irq
  intr_request_irq(LOOPBACK_IRQ, loopback_isr, INTR_IRQ_SHARED, dev->name, dev);

  debugf("initialized, dev=%s", dev->name);
  return dev;
}
