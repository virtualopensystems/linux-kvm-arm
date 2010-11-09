/*
 *  linux/arch/arm/mach-vexpress/platsmp.c
 *
 *  Copyright (C) 2002 ARM Ltd.
 *  All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#include <linux/init.h>
#include <linux/errno.h>
#include <linux/smp.h>
#include <linux/io.h>

#include <asm/smp_plat.h>
#include <asm/soc.h>
#include <asm/hardware/gic.h>

#include <mach/motherboard.h>

#include <plat/platsmp.h>

#include "core.h"

/*
 * Initialise the CPU possible map early - this describes the CPUs
 * which may be present or become present in the system.
 */
static void __init vexpress_smp_init_cpus(void)
{
	set_smp_cross_call(gic_raise_softirq);
	ct_desc->init_cpu_map();
}

static void __init vexpress_smp_prepare_cpus(unsigned int max_cpus)
{
	/*
	 * Initialise the present map, which describes the set of CPUs
	 * actually populated at the present time.
	 */
	ct_desc->smp_enable(max_cpus);

	/*
	 * Write the address of secondary startup into the
	 * system-wide flags register. The boot monitor waits
	 * until it receives a soft interrupt, and then the
	 * secondary CPU branches to this address.
	 */
	writel(~0, MMIO_P2V(V2M_SYS_FLAGSCLR));
	writel(virt_to_phys(versatile_secondary_startup),
		MMIO_P2V(V2M_SYS_FLAGSSET));
}

struct arm_soc_smp_init_ops vexpress_soc_smp_init_ops __initdata = {
	.smp_init_cpus		= vexpress_smp_init_cpus,
	.smp_prepare_cpus	= vexpress_smp_prepare_cpus,
};

struct arm_soc_smp_ops vexpress_soc_smp_ops __initdata = {
	.smp_secondary_init	= versatile_secondary_init,
	.smp_boot_secondary	= versatile_boot_secondary,
#ifdef CONFIG_HOTPLUG_CPU
	.cpu_kill		= dummy_cpu_kill,
	.cpu_die		= vexpress_cpu_die,
	.cpu_disable		= dummy_cpu_disable,
#endif
};
