/*
 *  linux/arch/arm/kernel/percpu_timer.c
 *
 *  Copyright (C) 2011 ARM Ltd.
 *  All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/irq.h>
#include <linux/seq_file.h>
#include <linux/interrupt.h>

#include <asm/localtimer.h>
#include <asm/hardware/gic.h>

#ifdef CONFIG_GENERIC_CLOCKEVENTS_BROADCAST
static void broadcast_timer_set_mode(enum clock_event_mode mode,
	struct clock_event_device *evt)
{
}
#else
#define broadcast_timer_set_mode	NULL
#define smp_timer_broadcast		NULL
#endif

static void broadcast_timer_setup(struct clock_event_device *evt)
{
	/* check that no-one has registered the timer in plat_setup */
	if (evt->name)
		return;

	evt->name	= "dummy_timer";
	evt->features	= CLOCK_EVT_FEAT_ONESHOT |
			  CLOCK_EVT_FEAT_PERIODIC |
			  CLOCK_EVT_FEAT_DUMMY;
	evt->rating	= 400;
	evt->mult	= 1;
	evt->set_mode	= broadcast_timer_set_mode;
	evt->broadcast	= smp_timer_broadcast;

	clockevents_register_device(evt);
}

static struct local_timer_ops broadcast_timer_ops = {
	.setup	= broadcast_timer_setup,
};

static struct local_timer_ops *timer_ops = &broadcast_timer_ops;

void percpu_timer_register(struct local_timer_ops *ops)
{
	timer_ops = ops;
}

/*
 * local_timer_ack: checks for a local timer interrupt.
 *
 * If a local timer interrupt has occurred, acknowledge and return 1.
 * Otherwise, return 0.
 *
 * This can be overloaded by platform code that doesn't provide its
 * timer in timer_fns way (msm at the moment). Once all platforms have
 * migrated, the weak alias can be removed.
 * If no ack() function has been registered, consider the acknowledgement
 * to be done.
 */
static int percpu_timer_ack(void)
{
	if (timer_ops->ack)
		return timer_ops->ack();

	return 1;
}

int local_timer_ack(void) __attribute__ ((weak, alias("percpu_timer_ack")));

/*
 * Timer (local or broadcast) support
 */
static DEFINE_PER_CPU(struct clock_event_device, percpu_clockevent);

irqreturn_t percpu_timer_handler(int irq, void *dev_id)
{
	struct clock_event_device *evt = dev_id;

	if (!evt)
		evt = &__get_cpu_var(percpu_clockevent);

	if (local_timer_ack()) {
		evt->event_handler(evt);
		return IRQ_HANDLED;
	}

	return IRQ_NONE;
}

void __cpuinit percpu_timer_setup(void)
{
	int ret = 0;
	unsigned int cpu = smp_processor_id();
	struct clock_event_device *evt = &per_cpu(percpu_clockevent, cpu);

	if (evt->name)
		return;

	evt->cpumask = cpumask_of(cpu);

	if (timer_ops->pre_setup)
		timer_ops->pre_setup(evt);
	if (timer_ops->plat_setup)
		ret = timer_ops->plat_setup(evt);
	if (ret)	/* Fallback to broadcast */
		timer_ops = &broadcast_timer_ops;
	if (timer_ops->setup)
		timer_ops->setup(evt);
}

#ifdef CONFIG_HOTPLUG_CPU
/*
 * The generic clock events code purposely does not stop the local timer
 * on CPU_DEAD/CPU_DEAD_FROZEN hotplug events, so we have to do it
 * manually here.
 */
void percpu_timer_stop(void)
{
	unsigned int cpu = smp_processor_id();
	struct clock_event_device *evt = &per_cpu(percpu_clockevent, cpu);

	evt->set_mode(CLOCK_EVT_MODE_UNUSED, evt);
	if (timer_ops->plat_teardown)
		timer_ops->plat_teardown(evt);

	/* Hack: mark the clock event device as unused */
	evt->name = NULL;
}
#endif
