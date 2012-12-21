/*
 * Vexpress big.LITTLE CPUFreq Interface driver
 *
 * It provides necessary ops to arm_big_little cpufreq driver and gets
 * information from spc controller.
 *
 * Copyright (C) 2012 ARM Ltd.
 * Author: Sudeep KarkadaNagesha <sudeep.karkadanagesha@arm.com>
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
#include <linux/types.h>
#include <linux/vexpress.h>
#include "arm_big_little.h"

static struct cpufreq_frequency_table *vexpress_get_freq_tbl(u32 cluster,
		int *count)
{
	unsigned int *table = vexpress_spc_get_freq_table(cluster, count);

	if (!table || !*count) {
		pr_err("SPC controller returned invalid freq table");
		return NULL;
	}

	return arm_bl_copy_table_from_array(table, *count);
}

static void vexpress_put_freq_tbl(u32 cluster)
{
	arm_bl_free_freq_table(cluster);
}

static struct cpufreq_arm_bl_ops vexpress_bl_ops = {
	.name	= "vexpress-bl",
	.get_freq_tbl = vexpress_get_freq_tbl,
	.put_freq_tbl = vexpress_put_freq_tbl,
};

static int vexpress_bl_init(void)
{
	if (!vexpress_spc_check_loaded()) {
		pr_info("%s: No SPC found\n", __func__);
		return -ENOENT;
	}

	return bl_cpufreq_register(&vexpress_bl_ops);
}
module_init(vexpress_bl_init);

static void vexpress_bl_exit(void)
{
	return bl_cpufreq_unregister(&vexpress_bl_ops);
}
module_exit(vexpress_bl_exit);

MODULE_DESCRIPTION("ARM Vexpress big LITTLE cpufreq driver");
MODULE_LICENSE("GPL");
