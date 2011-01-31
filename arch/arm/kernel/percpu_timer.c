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
 */
static int percpu_timer_ack(void)
{
	return timer_ops->ack();
}

asmlinkage void __exception_irq_entry do_local_timer(struct pt_regs *regs)
{
	struct pt_regs *old_regs = set_irq_regs(regs);
	int cpu = smp_processor_id();

	if (percpu_timer_ack()) {
		__inc_irq_stat(cpu, local_timer_irqs);
		percpu_timer_run();
	}

	set_irq_regs(old_regs);
}

void show_local_irqs(struct seq_file *p, int prec)
{
	unsigned int cpu;

	seq_printf(p, "%*s: ", prec, "LOC");

	for_each_present_cpu(cpu)
		seq_printf(p, "%10u ", __get_irq_stat(cpu, local_timer_irqs));

	seq_printf(p, " Local timer interrupts\n");
}

/*
 * Timer (local or broadcast) support
 */
static DEFINE_PER_CPU(struct clock_event_device, percpu_clockevent);

void percpu_timer_run(void)
{
	struct clock_event_device *evt = &__get_cpu_var(percpu_clockevent);
	irq_enter();
	evt->event_handler(evt);
	irq_exit();
}

void __cpuinit percpu_timer_setup(void)
{
	unsigned int cpu = smp_processor_id();
	struct clock_event_device *evt = &per_cpu(percpu_clockevent, cpu);

	if (evt->name)
		return;

	evt->cpumask = cpumask_of(cpu);

	if (timer_ops->plat_setup)
		timer_ops->plat_setup(evt);
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
}
#endif
