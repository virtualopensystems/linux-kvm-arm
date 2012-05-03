/*
 * arch/arm/mach-vexpress/dcscb.c - Dual Cluster System Control Block
 *
 * Created by:	Nicolas Pitre, May 2012
 * Copyright:	(C) 2012  Linaro Limited
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/io.h>
#include <linux/spinlock.h>
#include <linux/errno.h>
#include <linux/vexpress.h>

#include <asm/bL_entry.h>
#include <asm/proc-fns.h>
#include <asm/cacheflush.h>


#define DCSCB_PHYS_BASE	0x60000000

#define RST_HOLD0	0x0
#define RST_HOLD1	0x4
#define SYS_SWRESET	0x8
#define RST_STAT0	0xc
#define RST_STAT1	0x10
#define EAG_CFG_R	0x20
#define EAG_CFG_W	0x24
#define KFC_CFG_R	0x28
#define KFC_CFG_W	0x2c
#define DCS_CFG_R	0x30

/*
 * We can't use regular spinlocks. In the switcher case, it is possible
 * for an outbound CPU to call power_down() after its inbound counterpart
 * is already live using the same logical CPU number which trips lockdep
 * debugging.
 */
static arch_spinlock_t dcscb_lock = __ARCH_SPIN_LOCK_UNLOCKED;

static void __iomem *dcscb_base;

static int dcscb_power_up(unsigned int cpu, unsigned int cluster)
{
	unsigned int rst_hold, cpumask = (1 << cpu);

	pr_debug("%s: cpu %u cluster %u\n", __func__, cpu, cluster);
	if (cpu >= 4 || cluster >= 2)
		return -EINVAL;

	/*
	 * Since this is called with IRQs enabled, and no arch_spin_lock_irq
	 * variant exists, we need to disable IRQs manually here.
	 */
	local_irq_disable();
	arch_spin_lock(&dcscb_lock);

	rst_hold = readl_relaxed(dcscb_base + RST_HOLD0 + cluster * 4);
	if (rst_hold & (1 << 8)) {
		/* remove cluster reset and add individual CPU's reset */
		rst_hold &= ~(1 << 8);
		rst_hold |= 0xf;
	}
	rst_hold &= ~(cpumask | (cpumask << 4));
	writel(rst_hold, dcscb_base + RST_HOLD0 + cluster * 4);

	arch_spin_unlock(&dcscb_lock);
	local_irq_enable();

	return 0;
}

static void dcscb_power_down(void)
{
	unsigned int mpidr, cpu, cluster, rst_hold, cpumask, last_man;

	asm ("mrc p15, 0, %0, c0, c0, 5" : "=r" (mpidr));
	cpu = mpidr & 0xff;
	cluster = (mpidr >> 8) & 0xff;
	cpumask = (1 << cpu);

	pr_debug("%s: cpu %u cluster %u\n", __func__, cpu, cluster);
	BUG_ON(cpu >= 4 || cluster >= 2);

	arch_spin_lock(&dcscb_lock);
	rst_hold = readl_relaxed(dcscb_base + RST_HOLD0 + cluster * 4);
	rst_hold |= cpumask;
	if (((rst_hold | (rst_hold >> 4)) & 0xf) == 0xf)
		rst_hold |= (1 << 8);
	writel(rst_hold, dcscb_base + RST_HOLD0 + cluster * 4);
	arch_spin_unlock(&dcscb_lock);
	last_man = (rst_hold & (1 << 8));

	/*
	 * Now let's clean our L1 cache and shut ourself down.
	 * If we're the last CPU in this cluster then clean L2 too.
	 */

	/*
	 * A15/A7 can hit in the cache with SCTLR.C=0, so we don't need
	 * a preliminary flush here for those CPUs.  At least, that's
	 * the theory -- without the extra flush, Linux explodes on
	 * RTSM (maybe not needed anymore, to be investigated)..
	 */
	flush_cache_louis();
	cpu_proc_fin();

	if (!last_man) {
		flush_cache_louis();
	} else {
		flush_cache_all();
		outer_flush_all();
	}

	/* Disable local coherency by clearing the ACTLR "SMP" bit: */
	asm volatile (
		"mrc	p15, 0, ip, c1, c0, 1 \n\t"
		"bic	ip, ip, #(1 << 6) @ clear SMP bit \n\t"
		"mcr	p15, 0, ip, c1, c0, 1"
		: : : "ip" );

	/* Now we are prepared for power-down, do it: */
	wfi();

	/* Not dead at this point?  Let our caller cope. */
}

static const struct bL_platform_power_ops dcscb_power_ops = {
	.power_up	= dcscb_power_up,
	.power_down	= dcscb_power_down,
};

static int __init dcscb_init(void)
{
	int ret;

	dcscb_base = ioremap(DCSCB_PHYS_BASE, 0x1000);
	if (!dcscb_base)
		return -ENOMEM;

	ret = bL_platform_power_register(&dcscb_power_ops);
	if (ret) {
		iounmap(dcscb_base);
		return ret;
	}

	/*
	 * Future entries into the kernel can now go
	 * through the b.L entry vectors.
	 */
	vexpress_flags_set(virt_to_phys(bL_entry_point));

	return 0;
}

early_initcall(dcscb_init);
