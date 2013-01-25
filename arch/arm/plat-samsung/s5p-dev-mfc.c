/*
 * Copyright (C) 2010-2011 Samsung Electronics Co.Ltd
 *
 * Base S5P MFC resource and device definitions
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/kernel.h>
#include <linux/interrupt.h>
#include <linux/platform_device.h>
#include <linux/dma-mapping.h>
#include <linux/dma-contiguous.h>
#include <linux/memblock.h>
#include <linux/ioport.h>
#include <linux/of_fdt.h>
#include <linux/of.h>

#include <mach/map.h>
#include <plat/devs.h>
#include <plat/irqs.h>
#include <plat/mfc.h>

void __init s5p_mfc_reserve_mem(phys_addr_t rbase, unsigned int rsize,
				phys_addr_t lbase, unsigned int lsize)
{
	if (dma_declare_contiguous(&s5p_device_mfc_r.dev, rsize, rbase, 0))
		printk(KERN_ERR "Failed to reserve memory for MFC device (%u bytes at 0x%08lx)\n",
		       rsize, (unsigned long) rbase);

	if (dma_declare_contiguous(&s5p_device_mfc_l.dev, lsize, lbase, 0))
		printk(KERN_ERR "Failed to reserve memory for MFC device (%u bytes at 0x%08lx)\n",
		       rsize, (unsigned long) rbase);
}

#ifdef CONFIG_OF
int __init s5p_fdt_find_mfc_mem(unsigned long node, const char *uname,
				int depth, void *data)
{
	__be32 *prop;
	unsigned long len;
	struct s5p_mfc_dt_meminfo *mfc_mem = data;

	if (!data)
		return 0;

	if (!of_flat_dt_is_compatible(node, mfc_mem->compatible))
		return 0;

	prop = of_get_flat_dt_prop(node, "samsung,mfc-l", &len);
	if (!prop || (len != 2 * sizeof(unsigned long)))
		return 0;

	mfc_mem->loff = be32_to_cpu(prop[0]);
	mfc_mem->lsize = be32_to_cpu(prop[1]);

	prop = of_get_flat_dt_prop(node, "samsung,mfc-r", &len);
	if (!prop || (len != 2 * sizeof(unsigned long)))
		return 0;

	mfc_mem->roff = be32_to_cpu(prop[0]);
	mfc_mem->rsize = be32_to_cpu(prop[1]);

	return 1;
}
#endif
