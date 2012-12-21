/*
 * Generic big.LITTLE CPUFreq Interface driver
 *
 * It provides necessary ops to arm_big_little cpufreq driver and gets
 * Frequency information from Device Tree. Freq table in DT must be in KHz.
 *
 * Copyright (C) 2012 Linaro.
 * Viresh Kumar <viresh.kumar@linaro.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed "as is" WITHOUT ANY WARRANTY of any
 * kind, whether express or implied; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/cpufreq.h>
#include <linux/export.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/slab.h>
#include <linux/types.h>
#include "arm_big_little.h"

static struct cpufreq_frequency_table *generic_get_freq_tbl(u32 cluster,
		int *count)
{
	struct device_node *np = NULL;
	const struct property *pp;
	unsigned int *table = NULL;
	int cluster_id;
	struct cpufreq_frequency_table *cpufreq_table;

	while ((np = of_find_node_by_name(np, "cluster"))) {
		if (of_property_read_u32(np, "reg", &cluster_id))
			continue;

		if (cluster_id != cluster)
			continue;

		pp = of_find_property(np, "freqs", NULL);
		if (!pp)
			continue;

		*count = pp->length / sizeof(u32);
		if (!*count)
			continue;

		table = kmalloc(sizeof(*table) * (*count), GFP_KERNEL);
		if (!table) {
			pr_err("%s: Failed to allocate memory for table\n",
					__func__);
			return NULL;
		}

		of_property_read_u32_array(np, "freqs", table, *count);
		break;
	}

	if (!table) {
		pr_err("%s: Unable to retrieve Freq table from Device Tree",
				__func__);
		return NULL;
	}

	cpufreq_table = arm_bl_copy_table_from_array(table, *count);
	kfree(table);

	return cpufreq_table;
}

static void generic_put_freq_tbl(u32 cluster)
{
	arm_bl_free_freq_table(cluster);
}

static struct cpufreq_arm_bl_ops generic_bl_ops = {
	.name	= "generic-bl",
	.get_freq_tbl = generic_get_freq_tbl,
	.put_freq_tbl = generic_put_freq_tbl,
};

static int generic_bl_init(void)
{
	return bl_cpufreq_register(&generic_bl_ops);
}
module_init(generic_bl_init);

static void generic_bl_exit(void)
{
	return bl_cpufreq_unregister(&generic_bl_ops);
}
module_exit(generic_bl_exit);

MODULE_DESCRIPTION("Generic ARM big LITTLE cpufreq driver");
MODULE_LICENSE("GPL");
