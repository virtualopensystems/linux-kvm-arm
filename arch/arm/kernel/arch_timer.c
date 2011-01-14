/*
 *  linux/arch/arm/kernel/arch_timer.c
 *
 *  Copyright (C) 2011 ARM Ltd.
 *  All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/delay.h>
#include <linux/device.h>
#include <linux/smp.h>
#include <linux/jiffies.h>
#include <linux/clockchips.h>
#include <linux/irq.h>
#include <linux/io.h>

#include <asm/cputype.h>
#include <asm/localtimer.h>
#include <asm/sched_clock.h>
#include <asm/hardware/gic.h>

static unsigned long arch_timer_rate;

static DEFINE_CLOCK_DATA(cd);

/*
 * Architected system timer support.
 */

#define ARCH_TIMER_CTRL_ENABLE		(1 << 0)
#define ARCH_TIMER_CTRL_IT_MASK		(1 << 1)

#define ARCH_TIMER_REG_CTRL		0
#define ARCH_TIMER_REG_FREQ		1
#define ARCH_TIMER_REG_TVAL		2

static void arch_timer_reg_write(int reg, u32 val)
{
	switch (reg) {
	case ARCH_TIMER_REG_CTRL:
		asm volatile("mcr p15, 0, %0, c14, c2, 1" : : "r" (val));
		break;
	case ARCH_TIMER_REG_TVAL:
		asm volatile("mcr p15, 0, %0, c14, c2, 0" : : "r" (val));
		break;
	}

	isb();
}

static u32 arch_timer_reg_read(int reg)
{
	u32 val;

	switch (reg) {
	case ARCH_TIMER_REG_CTRL:
		asm volatile("mrc p15, 0, %0, c14, c2, 1" : "=r" (val));
		break;
	case ARCH_TIMER_REG_FREQ:
		asm volatile("mrc p15, 0, %0, c14, c0, 0" : "=r" (val));
		break;
	case ARCH_TIMER_REG_TVAL:
		asm volatile("mrc p15, 0, %0, c14, c2, 0" : "=r" (val));
		break;
	default:
		BUG();
	}

	return val;
}

static int arch_timer_ack(void)
{
	unsigned long ctrl;

	ctrl = arch_timer_reg_read(ARCH_TIMER_REG_CTRL);
	if (ctrl & 0x4) {
		ctrl |= ARCH_TIMER_CTRL_IT_MASK;
		arch_timer_reg_write(ARCH_TIMER_REG_CTRL, ctrl);
		return 1;
	}

	return 0;
}

static void arch_set_mode(enum clock_event_mode mode,
			  struct clock_event_device *clk)
{
}

static int arch_set_next_event(unsigned long evt,
			       struct clock_event_device *unused)
{
	unsigned long ctrl;

	ctrl = arch_timer_reg_read(ARCH_TIMER_REG_CTRL);
	ctrl |= ARCH_TIMER_CTRL_ENABLE;
	ctrl &= ~ARCH_TIMER_CTRL_IT_MASK;

	arch_timer_reg_write(ARCH_TIMER_REG_TVAL, evt);
	arch_timer_reg_write(ARCH_TIMER_REG_CTRL, ctrl);

	return 0;
}

static void __cpuinit arch_timer_setup(struct clock_event_device *clk)
{
	unsigned long ctrl;

	/* Let's make sure the timer is off before doing anything else */
	ctrl = arch_timer_reg_read(ARCH_TIMER_REG_CTRL);
	ctrl &= ~ARCH_TIMER_CTRL_ENABLE;
	arch_timer_reg_write(ARCH_TIMER_REG_CTRL, ctrl);

	clk->features = CLOCK_EVT_FEAT_ONESHOT;
	clk->name = "arch_sys_timer";
	clk->rating = 350;
	clk->shift = 20;
	clk->mult = div_sc(arch_timer_rate, NSEC_PER_SEC, clk->shift);

	clk->max_delta_ns = clockevent_delta2ns(0xffffffff, clk);
	clk->min_delta_ns = clockevent_delta2ns(0xf, clk);
	clk->set_mode = arch_set_mode;
	clk->set_next_event = arch_set_next_event;

	/* Make sure our local interrupt controller has this enabled */
	gic_enable_ppi(clk->irq);

	clockevents_register_device(clk);
}

static struct local_timer_ops arch_timer_ops = {
	.setup		= arch_timer_setup,
	.ack		= arch_timer_ack,
};

/* Is the optional system timer available? */
static int local_timer_is_architected(void)
{
	return (cpu_architecture() >= CPU_ARCH_ARMv7) &&
	       ((read_cpuid_ext(CPUID_EXT_PFR1) >> 16) & 0xf) == 1;
}

static int arch_timer_available(void)
{
	unsigned long freq;

	if (!local_timer_is_architected())
		return 0;

	smp_rmb();

	if (arch_timer_rate == 0) {
		arch_timer_reg_write(ARCH_TIMER_REG_CTRL, 0);
		freq = arch_timer_reg_read(ARCH_TIMER_REG_FREQ);

		/* Check the timer frequency. */
		if (freq == 0) {
			pr_warn("Architected timer frequency not available\n");
			return 0;
		}

		arch_timer_rate = freq;
		smp_wmb();
		pr_info("Architected local timer running at %lu.%02luMHz.\n",
			arch_timer_rate / 1000000, (arch_timer_rate / 100000) % 100);
	}

	return 1;
}

static cycle_t arch_counter_read(struct clocksource *cs)
{
	u32 cvall, cvalh;

	asm volatile("mrrc p15, 0, %0, %1, c14" : "=r" (cvall), "=r" (cvalh));

	return ((cycle_t) cvalh << 32) | cvall;
}

static struct clocksource clocksource_counter = {
	.name	= "arch_sys_counter",
	.rating	= 400,
	.read	= arch_counter_read,
	.mask	= CLOCKSOURCE_MASK(56),
	.flags	= (CLOCK_SOURCE_IS_CONTINUOUS | CLOCK_SOURCE_VALID_FOR_HRES),
};

DEFINE_SCHED_CLOCK_FUNC(arch_timer_sched_clock)
{
	u32 cvall, cvalh;

	asm volatile("mrrc p15, 1, %0, %1, c14" : "=r" (cvall), "=r" (cvalh));

	/*
	 * The sched_clock infrastructure only knows about counters
	 * with at most 32bits. Forget about the upper 24 bits for the
	 * time being...
	 */
	return cyc_to_sched_clock(&cd, cvall, (u32)~0);
}

static void notrace arch_timer_update_sched_clock(void)
{
	u32 cvall, cvalh;

	asm volatile("mrrc p15, 1, %0, %1, c14" : "=r" (cvall), "=r" (cvalh));
	update_sched_clock(&cd, cvall, (u32)~0);
}

static int __init arch_timer_clocksource_init(void)
{
	struct clocksource *cs = &clocksource_counter;

	percpu_timer_setup();

	clocksource_register_hz(cs, arch_timer_rate);

	init_arch_sched_clock(&cd, arch_timer_update_sched_clock,
			      arch_timer_sched_clock, 32, arch_timer_rate);

	return 0;
}

int __init arch_timer_register_setup(void (*setup)(struct clock_event_device *))
{
	if (!arch_timer_available())
		return -ENODEV;

	percpu_timer_register_setup(&arch_timer_ops, setup);
	arch_timer_clocksource_init();
	return 0;
}
