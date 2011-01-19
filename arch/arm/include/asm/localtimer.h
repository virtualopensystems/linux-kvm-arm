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

#include <linux/clockchips.h>

#include <asm/smp_twd.h>
#include <asm/arch_timer.h>

struct seq_file;

/*
 * Setup a per-cpu timer, whether it be a local timer or dummy broadcast
 */
void percpu_timer_setup(void);

/*
 * Call a per-cpu timer handler
 */
void percpu_timer_run(void);

/*
 * Stop a per-cpu timer
 */
void percpu_timer_stop(void);

/*
 * Called from assembly, this is the local timer IRQ handler
 */
asmlinkage void do_local_timer(struct pt_regs *);

struct local_timer_ops {
	void	(*plat_setup)(struct clock_event_device *clk);
	void	(*const setup)(struct clock_event_device *clk);
	int	(*const ack)(void);
};

/*
 * Setup a local timer interrupt for a CPU.
 */
void local_timer_setup(struct clock_event_device *);

/*
 * Register a local timer.
 */
#ifdef CONFIG_LOCAL_TIMERS
void percpu_timer_register(struct local_timer_ops *);
#else
static inline void percpu_timer_register(void *dummy)
{
}
#endif

static inline int percpu_timer_register_setup(struct local_timer_ops *ops,
					      void (*plat_setup)(struct clock_event_device *))
{
	if (ops) {
		ops->plat_setup = plat_setup;
		percpu_timer_register(ops);
		return 0;
	}

	return -1;
}

/*
 * show local interrupt info
 */
extern void show_local_irqs(struct seq_file *, int);

#endif
