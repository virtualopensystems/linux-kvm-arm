/*
 * ARM big.LITTLE platform's CPUFreq header file
 *
 * Copyright (C) 2012 ARM Ltd.
 * Author: Sudeep KarkadaNagesha <sudeep.karkadanagesha@arm.com>
 *
 * Copyright (C) 2012 ARM Ltd.
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
#ifndef CPUFREQ_ARM_BIG_LITTLE_H
#define CPUFREQ_ARM_BIG_LITTLE_H

#include <linux/cpufreq.h>
#include <linux/types.h>

struct cpufreq_arm_bl_ops {
	struct cpufreq_frequency_table *(*get_freq_tbl)(u32 cluster, int *count);
	void (*put_freq_tbl)(u32 cluster);
};

struct cpufreq_frequency_table *
arm_bl_copy_table_from_array(unsigned int *table, int count);
void arm_bl_free_freq_table(u32 cluster);

#if defined(CONFIG_ARM_VEXPRESS_BL_CPUFREQ) || defined(CONFIG_ARM_VEXPRESS_BL_CPUFREQ_MODULE)
struct cpufreq_arm_bl_ops *vexpress_bl_get_ops(void);
#else
static struct cpufreq_arm_bl_ops *vexpress_bl_get_ops(void)
{
	return NULL;
}
#endif

#endif /* CPUFREQ_ARM_BIG_LITTLE_H */
