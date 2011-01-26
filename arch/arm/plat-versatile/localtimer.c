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

#include <asm/localtimer.h>
#include <asm/hardware/gic.h>
#include <mach/irqs.h>

/*
 * Setup the local clock events for a CPU.
 */
int __cpuinit local_timer_setup(struct clock_event_device *evt)
{
	evt->irq = gic_ppi_to_vppi(IRQ_LOCALTIMER);
	return 0;
}
