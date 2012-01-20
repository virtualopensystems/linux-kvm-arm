#ifndef __ASMARM_ARCH_TIMER_H
#define __ASMARM_ARCH_TIMER_H

#include <linux/ioport.h>

struct arch_timer {
	struct resource	res[2];
};

int arch_timer_register(struct arch_timer *);
int arch_timer_sched_clock_init(void);

#endif
