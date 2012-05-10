#ifndef __ASMARM_ARCH_TIMER_H
#define __ASMARM_ARCH_TIMER_H

#include <linux/clocksource.h>
#include <linux/interrupt.h>

#ifdef CONFIG_ARM_ARCH_TIMER
int arch_timer_of_register(void);
int arch_timer_sched_clock_init(void);
struct timecounter *arch_timer_get_timecounter(void);
void arch_timer_switch_to_phys(irq_handler_t);
#else
static inline int arch_timer_of_register(void)
{
	return -ENXIO;
}

static inline int arch_timer_sched_clock_init(void)
{
	return -ENXIO;
}

static inline struct timecounter *arch_timer_get_timecounter(void)
{
	return NULL;
}

static inline void arch_timer_switch_to_phys(irq_handler_t handler)
{
}
#endif

#endif
