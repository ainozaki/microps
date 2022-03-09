#include "intr.h"

#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

#include "net.h"
#include "platform.h"
#include "util.h"

static sigset_t sigmask;
// intr thread id
static pthread_t tid;
static struct irq_entry* irqs;
static pthread_barrier_t barrier;

struct irq_entry {
  struct irq_entry* next;
  unsigned int irq;
  int (*handler)(unsigned int irg, void* dev);
  int flags;  // c.f. share irq number
  char name[16];
  void* dev;
};

static int intr_timer_setup(struct itimerspec* interval) {
  timer_t id;

  if (timer_create(CLOCK_REALTIME, NULL, &id) == -1) {
    errorf("timer_create: %s", strerror(errno));
    return -1;
  }
  if (timer_settime(id, 0, interval, NULL) == -1) {
    errorf("timer_settime: %s", strerror(errno));
    return -1;
  }
  return 0;
}

int intr_request_irq(unsigned int irq,
                     int (*handler)(unsigned int irq, void* dev),
                     int flags,
                     const char* name,
                     void* dev) {
  struct irq_entry* entry;

  debugf("irq=%u, flags=%d, name=%s", irq, flags, name);
  for (entry = irqs; entry; entry = entry->next) {
    if (entry->irq == irq) {
      if (entry->flags ^ INTR_IRQ_SHARED || flags ^ INTR_IRQ_SHARED) {
        errorf(
            "failure in intr_request_irq. conflicts with already registerd "
            "IRQs");
        return -1;
      }
    }
  }
  entry = memory_alloc(sizeof(*entry));
  if (!entry) {
    errorf("memory_alloc() failure");
    return -1;
  }
  entry->irq = irq;
  entry->handler = handler;
  entry->flags = flags;
  strncpy(entry->name, name, sizeof(entry->name) - 1);
  entry->dev = dev;
  entry->next = irqs;
  irqs = entry;
  sigaddset(&sigmask, irq);
  debugf("register: irq=%d, name=%s", irq, name);
  return 0;
}

int intr_raise_irq(unsigned int irq) {
  return pthread_kill(tid, (int)irq);
}

// Create thread for intr
static void* intr_thread(void* arg) {
  int terminate = 0;
  int sig;
  int err;
  struct irq_entry* entry;

  const struct timespec ts = {0, 1000000};
  struct itimerspec interval = {ts, ts};

  debugf("start...");
  pthread_barrier_wait(&barrier);

  if (intr_timer_setup(&interval) == -1) {
    errorf("intr_timer_setup() failure");
    return NULL;
  }

  while (!terminate) {
    err = sigwait(&sigmask, &sig);
    if (err) {
      errorf("err: sigwait %s", strerror(err));
      break;
    }

    switch (sig) {
      case SIGHUP:
        terminate = 1;
        break;
      case SIGUSR1:
        net_softirq_handler();
        break;
      case SIGUSR2:
        net_event_handler();
        break;
      case SIGALRM:
        net_timer_handler();
        break;
      default:
        for (entry = irqs; entry; entry = entry->next) {
          if (entry->irq == (unsigned int)sig) {
            debugf("irq=%d, name=%s", entry->irq, entry->name);
            entry->handler(entry->irq, entry->dev);
          }
        }
        break;
    }
  }
  debugf("terminated");
  return NULL;
}

int intr_run(void) {
  int err;

  err = pthread_sigmask(SIG_BLOCK, &sigmask, NULL);
  if (err) {
    errorf("err: pthread_sigmask %s", strerror(err));
    return -1;
  }

  err = pthread_create(&tid, NULL, intr_thread, NULL);
  if (err) {
    errorf("err: pthread_create %s", strerror(err));
    return -1;
  }

  pthread_barrier_wait(&barrier);
  return 0;
}

void intr_shutdown(void) {
  if (pthread_equal(tid, pthread_self()) != 0) {
    return;
  }
  pthread_kill(tid, SIGHUP);
  pthread_join(tid, NULL);
}

int intr_init(void) {
  // Set main thread id to tid
  tid = pthread_self();
  pthread_barrier_init(&barrier, NULL, 2);
  // Make sigmask empty
  sigemptyset(&sigmask);
  // Add to sigmask
  sigaddset(&sigmask, SIGHUP);
  sigaddset(&sigmask, SIGUSR1);
  sigaddset(&sigmask, SIGUSR2);
  sigaddset(&sigmask, SIGALRM);
  return 0;
}
