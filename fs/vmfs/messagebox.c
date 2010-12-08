/*
 * Copyright 2008-2009 ARM Limited. All rights reserved.
 */

/*
    Very simple linux 2.6 implementation of a messagebox
    for passing messages (data) between the vm and a device.

    Currently this implements just enough to satisfy the needs of VFS

    There are lots of TODOs here:
        clean up the device interface
        add support for delayed message response (PENDING vs OK/ERROR)
        add support for multiple users (vmfs currently does the locking)
*/

#include <linux/types.h>
#include <linux/mm.h>
#include <linux/io.h>
#include <linux/ioport.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/interrupt.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,28)
#include <linux/semaphore.h>
#endif

#include "vmfs_debug.h"

#include "mboxtypes.h"
#include "messagebox.h"

#if 0
#ifdef MESSAGEBOX_DEBUG
#define DEBUG1(f, a...) printk(KERN_DEBUG "%s: " f, __FUNCTION__ , ## a)
#else
#define DEBUG1(f, a...) do { ; } while(0)
#endif
#endif

// Define this to make the driver use PIO rather than memory mapped access
// #define USE_PIO

// Define this to use interrupts rather than polling - not quite working yet
#define USE_IRQ

// Message box device register layout in memory

typedef struct MBRegs
{
    uint32_t id;
    uint32_t data;
    uint32_t control;
    uint32_t status;
    uint32_t start;
    uint32_t end;
    uint32_t irqmask;
} MBRegs;

struct MessageBox
{
    volatile MBRegs* dev;       // virtual base of registers

    uint32_t dev_base;          // physical base of registers
    uint32_t dev_irq;           // irq number of device
    uint32_t* buffer;           // fixed size buffer used for passing data

#ifdef USE_IRQ
    // if we use IRQs then the calling thread must be able to sleep
    // and be woken by the IRQ handler. for this we appear to need a
    // wait queue
    wait_queue_head_t irq_queue;
    spinlock_t irq_lock;
#endif

    uint32_t use_irq;            // set to true if we're using irq's rather than polling

    struct semaphore mb_access;  // semaphore to allow only one thread to access the message box
};

#ifdef USE_IRQ
static irqreturn_t mb_interrupt(int irq, void* dev_id)
{
    MessageBox* mb = (MessageBox*)dev_id;

    FNENTER("");

    // should be safe to access the device here, or do we need to spinlock?
    spin_lock(&mb->irq_lock);

    // disable all interrupts, we only use RXREADY
    writel(0, &mb->dev->irqmask);

    // wake up any thread waiting on the queue
    wake_up_interruptible(&mb->irq_queue);

    spin_unlock(&mb->irq_lock);

    FNEXIT("");

    return IRQ_HANDLED;
}
#endif // USE_IRQ

// Initialise OS structures involved in serialising access to the messagebox
MessageBox* mb_new(uint32_t dev_base, uint32_t dev_irq)
{
    MessageBox* mb;

    DEBUG1("initialising at 0x%x ...\n", dev_base);

    mb = (MessageBox*)kmalloc(sizeof(MessageBox), GFP_KERNEL);

    // Map the messagebox registers and buffer int VM

    if (check_mem_region(dev_base, MBOX_DEVICE_SIZE))
    {
        DEBUG1("i/o space at 0x%x already in use\n", dev_base);
        return NULL;
    }

    request_mem_region(dev_base, MBOX_DEVICE_SIZE, "messagebox");
 
    mb->dev = ioremap_nocache(dev_base, MBOX_DEVICE_SIZE);

    DEBUG1("device registers mapped at %p, size 0x%x\n", mb->dev, MBOX_DEVICE_SIZE);

#ifdef USE_PIO
    mb->buffer = (uint32_t*)kmalloc(MBOX_BUFFER_SIZE, GFP_KERNEL);
#else
    mb->buffer = (uint32_t*)((uint8_t*)mb->dev + MBOX_BUFFER_BASE);
#endif

    // optionally request an interrupt source

#ifdef USE_IRQ
    mb->dev_irq = dev_irq;
    mb->use_irq = 1;
    if (request_irq(dev_irq, mb_interrupt, 0, "VFS", mb))
    {
        DEBUG1("failed to register irq %d\n", dev_irq);
        mb->use_irq = 0;
    }

    init_waitqueue_head(&mb->irq_queue);
    spin_lock_init(&mb->irq_lock);
#endif

    // set up a semaphore to restrict access to the message box

    sema_init(&mb->mb_access, 1);

    DEBUG1("initialised %p, id=0x%x\n", mb, mb_id(mb));


    return mb;
}

void mb_delete(MessageBox* mb)
{
#ifdef USE_IRQ
    if (mb->use_irq)
        free_irq(mb->dev_irq, mb);
#endif

    iounmap(mb->dev);

    release_mem_region(mb->dev_base, MBOX_DEVICE_SIZE);

#ifdef USE_PIO
    kfree(mb->buffer);
#endif

    kfree(mb);
}

// the message box should be locked by the thread during the send/receive cycle
int mb_lock(MessageBox* mb)
{
    return down_interruptible(&mb->mb_access);
}

void mb_unlock(MessageBox* mb)
{
    up(&mb->mb_access);
}

void* mb_start(MessageBox* mb, uint32_t len)
{
    /* start a message
     *
     * Current implementation expects exclusive access to the device
     * from mb_start to mb_end and through to mb_receive. 
     */
    writel(MBOX_CONTROL_START, &mb->dev->control);

    // reset buffer pointers

    writel(0, &mb->dev->start);
    writel(0, &mb->dev->end);

    return mb->buffer;
}

int mb_end(MessageBox* mb, uint32_t len)
{
#ifdef USE_PIO
    uint32_t* buffer = mb->buffer;

    len = len/4;

    while (len > 0)
    {
        writel(*buffer++, &mb->dev->data);
        --len;
    }   
#else
    writel(len, &mb->dev->end);
#endif

    /* Indicate to the device that all the buffered data is now written
     */
    writel(MBOX_CONTROL_END, &mb->dev->control);

    /* current implementation will set RXREADY to true to indicate
     * that the return data is available
     */
    return mb_ready(mb);
}

/* Indicate whether there is receive data ready to read */
int mb_ready(MessageBox* mb)
{
    return (readl(&mb->dev->status) & MBOX_STATUS_RXREADY) != 0;
}

/* Wait for the reply to become ready */
int mb_wait(MessageBox* mb)
{
#ifdef USE_IRQ
    if (mb->use_irq)
    {
        // add our thread to the irq wait queue
        DECLARE_WAITQUEUE(wait, current);

        add_wait_queue(&mb->irq_queue, &wait);
        do {
            

            // make ourself sleep interruptible
            set_current_state(TASK_INTERRUPTIBLE);

            // enable RXREADY interrupt
            spin_lock_irq(&mb->irq_lock);
                writel(MBOX_STATUS_RXREADY, &mb->dev->irqmask);
            spin_unlock_irq(&mb->irq_lock);

            DEBUG1("sleeping");

            // sleep
            schedule();

            DEBUG1("waking");

            // once there is data ready, break out
            if (mb_ready(mb))
                break;

           // if we were interrupted also break out
            if (signal_pending(current))
                break;
        }
        while (1);

        // back to normal
        remove_wait_queue(&mb->irq_queue, &wait);

        set_current_state(TASK_RUNNING);

        // ensure interrupts are masked out
        spin_lock_irq(&mb->irq_lock);
            writel(0, &mb->dev->irqmask);
        spin_unlock_irq(&mb->irq_lock);
       
        if (!mb_ready(mb))
            return -EINTR;
    }
#endif
    
    while (!mb_ready(mb))
        schedule();

    return 0;
}

void* mb_receive(MessageBox* mb, uint32_t* len)
{
#ifdef USE_PIO
    uint32_t* buffer = mb->buffer;
    uint32_t bidx = 0;

    /* read data from the device until there is no more to receive
     */

    while ((readl(&mb->dev->status) & MBOX_STATUS_RXEMPTY) == 0)
        buffer[bidx++] = readl(&mb->dev->data);

    *len = bidx*4;

    return mb->buffer;
#else
    uint32_t start = readl(&mb->dev->start);
    uint32_t end   = readl(&mb->dev->end);

    *len = end-start;

    return mb->buffer + start;
#endif
}

uint32_t mb_id(MessageBox* mb)
{
    return readl(&mb->dev->id);
}
