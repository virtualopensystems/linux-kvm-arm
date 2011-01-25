/*
 *  arch/arm/include/asm/localtimer.h
 *
 *  Copyright (C) 2004-2005 ARM Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#ifndef __ASM_ARM_LOCALTIMER_H
#define __ASM_ARM_LOCALTIMER_H

#include <linux/interrupt.h>
#include <linux/clockchips.h>

struct seq_file;

/*
 * Setup a per-cpu timer, whether it be a local timer or dummy broadcast
 */
void percpu_timer_setup(void);

/*
 * Per-cpu timer IRQ handler
 */
irqreturn_t percpu_timer_handler(int irq, void *dev_id);

/*
 * Stop a per-cpu timer
 */
void percpu_timer_stop(void);

struct local_timer_ops {
	void	(*const pre_setup)(struct clock_event_device *clk);
	int	(*plat_setup)(struct clock_event_device *clk);
	void	(*plat_teardown)(struct clock_event_device *clk);
	void	(*const setup)(struct clock_event_device *clk);
	int	(*const ack)(void);
};

#ifdef CONFIG_LOCAL_TIMERS
/*
 * Register a local timer.
 */
void percpu_timer_register(struct local_timer_ops *);
#else
static inline void percpu_timer_register(void *dummy)
{
}
#endif

static inline int percpu_timer_register_setup(struct local_timer_ops *ops,
					      int (*plat_setup)(struct clock_event_device *),
					      void (*plat_teardown)(struct clock_event_device *))
{
	if (ops) {
		ops->plat_setup = plat_setup;
		ops->plat_teardown = plat_teardown;
		percpu_timer_register(ops);
		return 0;
	}

	return -ENODEV;
}

#endif
