/*
 *  linux/arch/arm/common/gic.c
 *
 *  Copyright (C) 2002 ARM Limited, All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Interrupt architecture for the GIC:
 *
 * o There is one Interrupt Distributor, which receives interrupts
 *   from system devices and sends them to the Interrupt Controllers.
 *
 * o There is one CPU Interface per CPU, which sends interrupts sent
 *   by the Distributor, and interrupts generated locally, to the
 *   associated CPU. The base address of the CPU interface is usually
 *   aliased so that the same address points to different chips depending
 *   on the CPU it is accessed from.
 *
 * Note that IRQs 0-31 are special - they are local to each CPU.
 * As such, the enable set/clear, pending set/clear and active bit
 * registers are banked per-cpu for these sources.
 */
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/smp.h>
#include <linux/cpumask.h>
#include <linux/io.h>

#include <asm/irq.h>
#include <asm/mach/irq.h>
#include <asm/hardware/gic.h>

static DEFINE_SPINLOCK(irq_controller_lock);

/* Address of GIC 0 CPU interface */
void __iomem *gic_cpu_base_addr __read_mostly;

struct gic_chip_data {
	unsigned int irq_offset;
	void __iomem *dist_base;
	void __iomem *cpu_base;
#ifdef CONFIG_ARM_GIC_VPPI
	/* These fields must be 0 on secondary GICs */
	int	     ppi_base;
	int	     vppi_base;
	u16	     nrppis;
#endif
};

/*
 * Supported arch specific GIC irq extension.
 * Default make them NULL.
 */
struct irq_chip gic_arch_extn = {
	.irq_eoi	= NULL,
	.irq_mask	= NULL,
	.irq_unmask	= NULL,
	.irq_retrigger	= NULL,
	.irq_set_type	= NULL,
	.irq_set_wake	= NULL,
};

#ifndef MAX_GIC_NR
#define MAX_GIC_NR	1
#endif

static struct gic_chip_data gic_data[MAX_GIC_NR] __read_mostly;

static inline void __iomem *gic_dist_base(struct irq_data *d)
{
	struct gic_chip_data *gic_data = irq_data_get_irq_chip_data(d);
	return gic_data->dist_base;
}

static inline void __iomem *gic_cpu_base(struct irq_data *d)
{
	struct gic_chip_data *gic_data = irq_data_get_irq_chip_data(d);
	return gic_data->cpu_base;
}

static inline unsigned int gic_irq(struct irq_data *d)
{
	struct gic_chip_data *gic_data = irq_data_get_irq_chip_data(d);
	return d->irq - gic_data->irq_offset;
}

/*
 * Routines to acknowledge, disable and enable interrupts
 */
static void gic_mask_irq(struct irq_data *d)
{
	u32 mask = 1 << (d->irq % 32);

	spin_lock(&irq_controller_lock);
	writel(mask, gic_dist_base(d) + GIC_DIST_ENABLE_CLEAR + (gic_irq(d) / 32) * 4);
	if (gic_arch_extn.irq_mask)
		gic_arch_extn.irq_mask(d);
	spin_unlock(&irq_controller_lock);
}

static void gic_unmask_irq(struct irq_data *d)
{
	u32 mask = 1 << (d->irq % 32);

	spin_lock(&irq_controller_lock);
	if (gic_arch_extn.irq_unmask)
		gic_arch_extn.irq_unmask(d);
	writel(mask, gic_dist_base(d) + GIC_DIST_ENABLE_SET + (gic_irq(d) / 32) * 4);
	spin_unlock(&irq_controller_lock);
}

static void gic_eoi_irq(struct irq_data *d)
{
	if (gic_arch_extn.irq_eoi) {
		spin_lock(&irq_controller_lock);
		gic_arch_extn.irq_eoi(d);
		spin_unlock(&irq_controller_lock);
	}

	writel(gic_irq(d), gic_cpu_base(d) + GIC_CPU_EOI);
}

static int gic_set_type(struct irq_data *d, unsigned int type)
{
	void __iomem *base = gic_dist_base(d);
	unsigned int gicirq = gic_irq(d);
	u32 enablemask = 1 << (gicirq % 32);
	u32 enableoff = (gicirq / 32) * 4;
	u32 confmask = 0x2 << ((gicirq % 16) * 2);
	u32 confoff = (gicirq / 16) * 4;
	bool enabled = false;
	u32 val;

	/* Interrupt configuration for SGIs can't be changed */
	if (gicirq < 16)
		return -EINVAL;

	if (type != IRQ_TYPE_LEVEL_HIGH && type != IRQ_TYPE_EDGE_RISING)
		return -EINVAL;

	spin_lock(&irq_controller_lock);

	if (gic_arch_extn.irq_set_type)
		gic_arch_extn.irq_set_type(d, type);

	val = readl(base + GIC_DIST_CONFIG + confoff);
	if (type == IRQ_TYPE_LEVEL_HIGH)
		val &= ~confmask;
	else if (type == IRQ_TYPE_EDGE_RISING)
		val |= confmask;

	/*
	 * As recommended by the spec, disable the interrupt before changing
	 * the configuration
	 */
	if (readl(base + GIC_DIST_ENABLE_SET + enableoff) & enablemask) {
		writel(enablemask, base + GIC_DIST_ENABLE_CLEAR + enableoff);
		enabled = true;
	}

	writel(val, base + GIC_DIST_CONFIG + confoff);

	if (enabled)
		writel(enablemask, base + GIC_DIST_ENABLE_SET + enableoff);

	spin_unlock(&irq_controller_lock);

	return 0;
}

static int gic_retrigger(struct irq_data *d)
{
	if (gic_arch_extn.irq_retrigger)
		return gic_arch_extn.irq_retrigger(d);

	return -ENXIO;
}

#ifdef CONFIG_SMP
static int gic_set_affinity(struct irq_data *d, const struct cpumask *mask_val,
			    bool force)
{
	void __iomem *reg = gic_dist_base(d) + GIC_DIST_TARGET + (gic_irq(d) & ~3);
	unsigned int shift = (d->irq % 4) * 8;
	unsigned int cpu = cpumask_first(mask_val);
	u32 val, mask, bit;

	if (cpu >= 8)
		return -EINVAL;

	mask = 0xff << shift;
	bit = 1 << (cpu + shift);

	spin_lock(&irq_controller_lock);
	d->node = cpu;
	val = readl(reg) & ~mask;
	writel(val | bit, reg);
	spin_unlock(&irq_controller_lock);

	return 0;
}
#endif

#ifdef CONFIG_PM
static int gic_set_wake(struct irq_data *d, unsigned int on)
{
	int ret = -ENXIO;

	if (gic_arch_extn.irq_set_wake)
		ret = gic_arch_extn.irq_set_wake(d, on);

	return ret;
}

#else
#define gic_set_wake	NULL
#endif

static void gic_handle_cascade_irq(unsigned int irq, struct irq_desc *desc)
{
	struct gic_chip_data *chip_data = irq_get_handler_data(irq);
	struct irq_chip *chip = irq_get_chip(irq);
	unsigned int cascade_irq, gic_irq;
	unsigned long status;

	chained_irq_enter(chip, desc);

	spin_lock(&irq_controller_lock);
	status = readl(chip_data->cpu_base + GIC_CPU_INTACK);
	spin_unlock(&irq_controller_lock);

	gic_irq = (status & 0x3ff);
	if (gic_irq == 1023)
		goto out;

	cascade_irq = gic_irq + chip_data->irq_offset;
	if (unlikely(gic_irq < 32 || gic_irq > 1020 || cascade_irq >= NR_IRQS))
		do_bad_IRQ(cascade_irq, desc);
	else
		generic_handle_irq(cascade_irq);

 out:
	chained_irq_exit(chip, desc);
}

static struct irq_chip gic_chip = {
	.name			= "GIC",
	.irq_mask		= gic_mask_irq,
	.irq_unmask		= gic_unmask_irq,
	.irq_eoi		= gic_eoi_irq,
	.irq_set_type		= gic_set_type,
	.irq_retrigger		= gic_retrigger,
#ifdef CONFIG_SMP
	.irq_set_affinity	= gic_set_affinity,
#endif
	.irq_set_wake		= gic_set_wake,
};

void __init gic_cascade_irq(unsigned int gic_nr, unsigned int irq)
{
	if (gic_nr >= MAX_GIC_NR)
		BUG();
	if (irq_set_handler_data(irq, &gic_data[gic_nr]) != 0)
		BUG();
	irq_set_chained_handler(irq, gic_handle_cascade_irq);
}

#ifdef CONFIG_ARM_GIC_VPPI
unsigned int gic_ppi_to_vppi(unsigned int irq)
{
	struct gic_chip_data *chip_data = irq_get_chip_data(irq);
	unsigned int vppi_irq;
	unsigned int ppi;

	WARN_ON(!chip_data->vppi_base);

	ppi = irq - chip_data->ppi_base;
	vppi_irq = ppi + chip_data->nrppis * smp_processor_id();
	vppi_irq += chip_data->vppi_base;

	return vppi_irq;
}

static void gic_handle_ppi(unsigned int irq, struct irq_desc *desc)
{
	unsigned int vppi_irq;

	vppi_irq = gic_ppi_to_vppi(irq);
	generic_handle_irq(vppi_irq);
}

static struct irq_data *gic_vppi_to_ppi(struct irq_data *d)
{
	struct gic_chip_data *chip_data = irq_data_get_irq_chip_data(d);
	unsigned int ppi_irq;

	ppi_irq = d->irq - chip_data->vppi_base - chip_data->nrppis * smp_processor_id();
	ppi_irq += chip_data->ppi_base;

	return irq_get_irq_data(ppi_irq);
}

static void gic_ppi_eoi_irq(struct irq_data *d)
{
	gic_eoi_irq(gic_vppi_to_ppi(d));
}

static void gic_ppi_mask_irq(struct irq_data *d)
{
	gic_mask_irq(gic_vppi_to_ppi(d));
}

static void gic_ppi_unmask_irq(struct irq_data *d)
{
	gic_unmask_irq(gic_vppi_to_ppi(d));
}

static int gic_ppi_set_type(struct irq_data *d, unsigned int type)
{
	return gic_set_type(gic_vppi_to_ppi(d), type);
}

#ifdef CONFIG_PM
static int gic_ppi_set_wake(struct irq_data *d, unsigned int on)
{
	return gic_set_wake(gic_vppi_to_ppi(d), on);
}
#else
#define gic_ppi_set_wake	NULL
#endif

static int __init gic_irq_is_ppi(struct gic_chip_data *gic, unsigned int irq)
{
	return (irq >= (gic->irq_offset + 16) && irq <= (gic->irq_offset + 31));
}

static struct irq_chip gic_ppi_chip = {
	.name			= "GIC-PPI",
	.irq_eoi		= gic_ppi_eoi_irq,
	.irq_mask		= gic_ppi_mask_irq,
	.irq_unmask		= gic_ppi_unmask_irq,
	.irq_set_type		= gic_ppi_set_type,
	.irq_set_wake		= gic_ppi_set_wake,
};
#endif

static void __init gic_dist_init(struct gic_chip_data *gic,
	unsigned int irq_start)
{
	unsigned int gic_irqs, irq_limit, i, nrvppis = 0;
	void __iomem *base = gic->dist_base;
	u32 cpumask = 1 << smp_processor_id();
	u32 dist_ctr, nrcpus;

	cpumask |= cpumask << 8;
	cpumask |= cpumask << 16;

	writel(0, base + GIC_DIST_CTRL);

	/*
	 * Find out how many interrupts are supported.
	 * The GIC only supports up to 1020 interrupt sources.
	 */
	dist_ctr = readl(base + GIC_DIST_CTR);
	gic_irqs = ((dist_ctr & 0x1f) + 1) * 32;
	if (gic_irqs > 1020)
		gic_irqs = 1020;

	/* Find out how many CPUs are supported (8 max). */
	nrcpus = ((dist_ctr >> 5) & 7) + 1;

#ifdef CONFIG_ARM_GIC_VPPI
	/*
	 * Nobody would be insane enough to use PPIs on a secondary
	 * GIC, right?
	 */
	if (gic == &gic_data[0]) {
		gic->nrppis = 16 - (irq_start % 16);
		gic->ppi_base = gic->irq_offset + 32 - gic->nrppis;
		nrvppis = gic->nrppis * nrcpus;
	} else {
		gic->ppi_base = 0;
		gic->vppi_base = 0;
	}
#endif

	pr_info("Configuring GIC with %d sources (%d additional PPIs)\n",
		gic_irqs, nrvppis);

	/*
	 * Set all global interrupts to be level triggered, active low.
	 */
	for (i = 32; i < gic_irqs; i += 16)
		writel(0, base + GIC_DIST_CONFIG + i * 4 / 16);

	/*
	 * Set all global interrupts to this CPU only.
	 */
	for (i = 32; i < gic_irqs; i += 4)
		writel(cpumask, base + GIC_DIST_TARGET + i * 4 / 4);

	/*
	 * Set priority on all global interrupts.
	 */
	for (i = 32; i < gic_irqs; i += 4)
		writel(0xa0a0a0a0, base + GIC_DIST_PRI + i * 4 / 4);

	/*
	 * Disable all interrupts.  Leave the PPI and SGIs alone
	 * as these enables are banked registers.
	 */
	for (i = 32; i < gic_irqs; i += 32)
		writel(0xffffffff, base + GIC_DIST_ENABLE_CLEAR + i * 4 / 32);

	/*
	 * Limit number of interrupts registered to the platform maximum
	 */
	irq_limit = gic->irq_offset + gic_irqs;
	if (WARN_ON(irq_limit > NR_IRQS))
		irq_limit = NR_IRQS;

	/*
	 * Setup the Linux IRQ subsystem.
	 */
	for (i = irq_start; i < irq_limit; i++) {
#ifdef CONFIG_ARM_GIC_VPPI
		if (nrvppis && gic_irq_is_ppi(gic, i))
			irq_set_chip_and_handler(i, &gic_chip, gic_handle_ppi);
		else
#endif
		{
			irq_set_chip_and_handler(i, &gic_chip,
						 handle_fasteoi_irq);
			set_irq_flags(i, IRQF_VALID | IRQF_PROBE);
		}
		irq_set_chip_data(i, gic);
	}

#ifdef CONFIG_ARM_GIC_VPPI
	if (!nrvppis)
		goto out;
	gic->vppi_base = irq_alloc_descs(-1, 0, nrvppis, 0);
	if (WARN_ON(gic->vppi_base < 0))
		goto out;
	for (i = gic->vppi_base; i < (gic->vppi_base + nrvppis); i++) {
		irq_set_chip_and_handler(i, &gic_ppi_chip, handle_percpu_irq);
		irq_set_chip_data(i, gic);
		set_irq_flags(i, IRQF_VALID | IRQF_PROBE);
	}
out:
#endif

	writel(1, base + GIC_DIST_CTRL);
}

static void __cpuinit gic_cpu_init(struct gic_chip_data *gic)
{
	void __iomem *dist_base = gic->dist_base;
	void __iomem *base = gic->cpu_base;
	int i;

	/*
	 * Deal with the banked PPI and SGI interrupts - disable all
	 * PPI interrupts, ensure all SGI interrupts are enabled.
	 */
	writel(0xffff0000, dist_base + GIC_DIST_ENABLE_CLEAR);
	writel(0x0000ffff, dist_base + GIC_DIST_ENABLE_SET);

	/*
	 * Set priority on PPI and SGI interrupts
	 */
	for (i = 0; i < 32; i += 4)
		writel(0xa0a0a0a0, dist_base + GIC_DIST_PRI + i * 4 / 4);

	writel(0xf0, base + GIC_CPU_PRIMASK);
	writel(1, base + GIC_CPU_CTRL);
}

void __init gic_init(unsigned int gic_nr, unsigned int irq_start,
	void __iomem *dist_base, void __iomem *cpu_base)
{
	struct gic_chip_data *gic;

	BUG_ON(gic_nr >= MAX_GIC_NR);

	gic = &gic_data[gic_nr];
	gic->dist_base = dist_base;
	gic->cpu_base = cpu_base;
	gic->irq_offset = (irq_start - 1) & ~31;

	if (gic_nr == 0)
		gic_cpu_base_addr = cpu_base;

	gic_dist_init(gic, irq_start);
	gic_cpu_init(gic);
}

void __cpuinit gic_secondary_init(unsigned int gic_nr)
{
	BUG_ON(gic_nr >= MAX_GIC_NR);

	gic_cpu_init(&gic_data[gic_nr]);
}

#ifdef CONFIG_SMP
void gic_raise_softirq(const struct cpumask *mask, unsigned int irq)
{
	unsigned long map = *cpus_addr(*mask);

	/* this always happens on GIC0 */
	writel(map << 16 | irq, gic_data[0].dist_base + GIC_DIST_SOFTINT);
}
#endif
