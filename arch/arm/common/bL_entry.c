/*
 * arch/arm/common/bL_entry.c -- big.LITTLE kernel re-entry point
 *
 * Created by:  Nicolas Pitre, March 2012
 * Copyright:   (C) 2012  Linaro Limited
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/kernel.h>
#include <linux/init.h>

#include <asm/bL_entry.h>
#include <asm/barrier.h>
#include <asm/proc-fns.h>
#include <asm/cacheflush.h>

extern volatile unsigned long bL_entry_vectors[BL_NR_CLUSTERS][BL_CPUS_PER_CLUSTER];

void bL_set_entry_vector(unsigned cpu, unsigned cluster, void *ptr)
{
	unsigned long val = ptr ? virt_to_phys(ptr) : 0;
	bL_entry_vectors[cluster][cpu] = val;
	smp_wmb();
	__cpuc_flush_dcache_area((void *)&bL_entry_vectors[cluster][cpu], 4);
	outer_clean_range(__pa(&bL_entry_vectors[cluster][cpu]),
			  __pa(&bL_entry_vectors[cluster][cpu + 1]));
}
