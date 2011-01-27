/*
 *  linux/arch/arm/plat-versatile/localtimer.c
 *
 *  Copyright (C) 2002 ARM Ltd.
 *  All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#include <linux/init.h>
#include <linux/clockchips.h>

#include <asm/smp_twd.h>
#include <asm/localtimer.h>
#include <asm/hardware/gic.h>
#include <mach/irqs.h>

/*
 * Setup the local clock events for a CPU.
 */
int __cpuinit versatile_local_timer_setup(struct clock_event_device *evt)
{
	evt->irq = gic_ppi_to_vppi(IRQ_LOCALTIMER);
	return 0;
}

void __init versatile_local_timer_init(void __iomem *base)
{
	if (base)
		twd_base = base;
	twd_timer_register_setup(versatile_local_timer_setup);
}
