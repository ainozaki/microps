#ifndef INTR_H_
#define INTR_H_

#define INTR_IRQ_SHARED 0x0001
// SIGRTMIN:34, SIGRTMAX64
// glibc uses 34
#define INTR_BASE        35
#define INTR_IRQ_SOFTIRQ SIGUSR1
#define INTR_IRQ_EVENT   SIGUSR2

// Register intr
int intr_request_irq(unsigned int irq,
                     int (*handler)(unsigned int irq, void* dev),
                     int flags,
                     const char* name,
                     void* dev);

// Send signal to intr thread
int intr_raise_irq(unsigned int irq);

int intr_run(void);
int intr_init(void);
void intr_shutdown(void);
#endif
