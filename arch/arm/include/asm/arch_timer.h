#ifndef __ASMARM_ARCH_TIMER_H
#define __ASMARM_ARCH_TIMER_H

#ifdef CONFIG_HAVE_ARCH_TIMERS
int arch_timer_register_setup(void (*setup)(struct clock_event_device *));
#else
static inline int arch_timer_register_setup(void (*setup)(struct clock_event_device *))
{
	return -ENODEV;
}
#endif

#endif
