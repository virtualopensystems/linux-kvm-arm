/*
 * ARM big.LITTLE Platforms CPUFreq support
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
#include <linux/cpumask.h>
#include <linux/module.h>
#include <linux/of_platform.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/vexpress.h>
#include <asm/topology.h>

#define MAX_CLUSTERS	2

static struct cpufreq_frequency_table *freq_table[MAX_CLUSTERS];
static atomic_t freq_table_users = ATOMIC_INIT(0);

/*
 * Functions to get the current status.
 *
 * Beware that the cluster for another CPU may change unexpectedly.
 */
static int cpu_to_cluster(int cpu)
{
	return topology_physical_package_id(cpu);
}

/* Validate policy frequency range */
static int bl_cpufreq_verify_policy(struct cpufreq_policy *policy)
{
	u32 cur_cluster = cpu_to_cluster(policy->cpu);

	/* This call takes care of it all using freq_table */
	return cpufreq_frequency_table_verify(policy, freq_table[cur_cluster]);
}

/* Set clock frequency */
static int bl_cpufreq_set_target(struct cpufreq_policy *policy,
		unsigned int target_freq, unsigned int relation)
{
	struct cpufreq_freqs freqs;
	u32 cpu = policy->cpu, freq_tab_idx, cur_cluster;
	int ret = 0;

	/* ASSUMPTION: The cpu can't be hotplugged in this function */
	cur_cluster = cpu_to_cluster(policy->cpu);

	if (vexpress_spc_get_performance(cur_cluster, &freqs.old))
		return -EIO;

	/* Determine valid target frequency using freq_table */
	cpufreq_frequency_table_target(policy, freq_table[cur_cluster],
			target_freq, relation, &freq_tab_idx);
	freqs.new = freq_table[cur_cluster][freq_tab_idx].frequency;

	freqs.cpu = policy->cpu;

	if (freqs.old == freqs.new)
		return 0;

	pr_debug("Requested Freq %d cpu %d\n", freqs.new, cpu);

	for_each_cpu(freqs.cpu, policy->cpus)
		cpufreq_notify_transition(&freqs, CPUFREQ_PRECHANGE);

	ret = vexpress_spc_set_performance(cur_cluster, freqs.new);
	if (ret) {
		pr_err("Error %d while setting required OPP\n", ret);
		return ret;
	}

	policy->cur = freqs.new;

	for_each_cpu(freqs.cpu, policy->cpus)
		cpufreq_notify_transition(&freqs, CPUFREQ_POSTCHANGE);

	return ret;
}

/* Get current clock frequency */
static unsigned int bl_cpufreq_get(unsigned int cpu)
{
	u32 freq = 0;
	u32 cur_cluster = cpu_to_cluster(cpu);

	/*
	 * Read current clock rate with vexpress_spc call
	 */
	if (vexpress_spc_get_performance(cur_cluster, &freq))
		return -EIO;

	return freq;
}

/* translate the integer array into cpufreq_frequency_table entries */
static inline void _cpufreq_copy_table_from_array(u32 *table,
			struct cpufreq_frequency_table *freq_table, int size)
{
	int i;
	for (i = 0; i < size; i++) {
		freq_table[i].index = i;
		freq_table[i].frequency = table[i] / 1000; /* in kHZ */
	}
	freq_table[i].index = size;
	freq_table[i].frequency = CPUFREQ_TABLE_END;
}

static int bl_cpufreq_of_init(void)
{
	u32 cpu_opp_num;
	struct cpufreq_frequency_table *freqtable[MAX_CLUSTERS];
	u32 *cpu_freqs;
	int ret = 0, cluster_id = 0, len;
	struct device_node *cluster = NULL;
	const struct property *pp;
	const u32 *hwid;

	while ((cluster = of_find_node_by_name(cluster, "cluster"))) {
		hwid = of_get_property(cluster, "reg", &len);
		if (hwid && len == 4)
			cluster_id = be32_to_cpup(hwid);

		pp = of_find_property(cluster, "freqs", NULL);
		if (!pp)
			return -EINVAL;
		cpu_opp_num = pp->length / sizeof(u32);
		if (!cpu_opp_num)
			return -ENODATA;

		cpu_freqs = kzalloc(sizeof(u32) * cpu_opp_num, GFP_KERNEL);
		freqtable[cluster_id] =
			kzalloc(sizeof(struct cpufreq_frequency_table) *
						(cpu_opp_num + 1), GFP_KERNEL);
		if (!cpu_freqs || !freqtable[cluster_id]) {
			ret = -ENOMEM;
			goto free_mem;
		}
		of_property_read_u32_array(cluster, "freqs",
							cpu_freqs, cpu_opp_num);
		_cpufreq_copy_table_from_array(cpu_freqs,
				freqtable[cluster_id], cpu_opp_num);
		freq_table[cluster_id] = freqtable[cluster_id];

		kfree(cpu_freqs);
	}
	return ret;
free_mem:
	while (cluster_id >= 0)
		kfree(freqtable[cluster_id--]);
	kfree(cpu_freqs);
	return ret;
}

/* Per-CPU initialization */
static int bl_cpufreq_init(struct cpufreq_policy *policy)
{
	int result = 0;
	u32 cur_cluster = cpu_to_cluster(policy->cpu);

	if (atomic_inc_return(&freq_table_users) == 1)
		result = bl_cpufreq_of_init();

	if (freq_table[cur_cluster] == NULL)
		result = -ENODATA;

	if (result) {
		atomic_dec_return(&freq_table_users);
		pr_err("CPUFreq - CPU %d failed to initialize\n", policy->cpu);
		return result;
	}

	result = cpufreq_frequency_table_cpuinfo(policy,
			freq_table[cur_cluster]);
	if (result)
		return result;

	cpufreq_frequency_table_get_attr(freq_table[cur_cluster], policy->cpu);

	/* set default policy and cpuinfo */
	policy->min = policy->cpuinfo.min_freq;
	policy->max = policy->cpuinfo.max_freq;

	policy->cpuinfo.transition_latency = 1000000;	/* 1 ms assumed */
	policy->cur = bl_cpufreq_get(policy->cpu);

	cpumask_copy(policy->cpus, topology_core_cpumask(policy->cpu));
	cpumask_copy(policy->related_cpus, policy->cpus);

	pr_info("CPUFreq for CPU %d initialized\n", policy->cpu);
	return result;
}

/* Export freq_table to sysfs */
static struct freq_attr *bl_cpufreq_attr[] = {
	&cpufreq_freq_attr_scaling_available_freqs,
	NULL,
};

static struct cpufreq_driver bl_cpufreq_driver = {
	.name	= "arm-big-little",
	.flags	= CPUFREQ_STICKY,
	.verify	= bl_cpufreq_verify_policy,
	.target	= bl_cpufreq_set_target,
	.get	= bl_cpufreq_get,
	.init	= bl_cpufreq_init,
	.attr	= bl_cpufreq_attr,
};

static int __init bl_cpufreq_modinit(void)
{
	if (!vexpress_spc_check_loaded()) {
		pr_info("vexpress cpufreq not initialised because no SPC found\n");
		return -ENODEV;
	}

	return cpufreq_register_driver(&bl_cpufreq_driver);
}
module_init(bl_cpufreq_modinit);

static void __exit bl_cpufreq_modexit(void)
{
	cpufreq_unregister_driver(&bl_cpufreq_driver);
}
module_exit(bl_cpufreq_modexit);

MODULE_DESCRIPTION("ARM big LITTLE platforms cpufreq driver");
MODULE_LICENSE("GPL");
