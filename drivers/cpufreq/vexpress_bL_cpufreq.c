/*
 * Vexpress big.LITTLE CPUFreq support
 * Based on mach-integrator
 *
 * Copyright (C) 2012 ARM Ltd.
 * Author: Sudeep KarkadaNagesha <sudeep.karkadanagesha@arm.com>
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
#include <linux/cpufreq.h>
#include <linux/cpumask.h>
#include <linux/init.h>
#include <linux/io.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/of_platform.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/smp.h>
#include <linux/spinlock.h>
#include <linux/sysfs.h>
#include <linux/types.h>

#include <linux/vexpress.h>

#define VEXPRESS_MAX_CLUSTER	2

static struct cpufreq_frequency_table *freq_table[VEXPRESS_MAX_CLUSTER];
static atomic_t freq_table_users = ATOMIC_INIT(0);

/* Cached current cluster for each CPU to save on IPIs */
static DEFINE_PER_CPU(unsigned int, cpu_cur_cluster);

/*
 * Functions to get the current status.
 *
 * Beware that the cluster for another CPU may change unexpectedly.
 */

static unsigned int get_local_cluster(void)
{
	unsigned int mpidr;
	asm ("mrc\tp15, 0, %0, c0, c0, 5" : "=r" (mpidr));
	return (mpidr >> 8) & 0xf;
}

static void __get_current_cluster(void *_data)
{
	unsigned int *_cluster = _data;
	*_cluster = get_local_cluster();
}

static int get_current_cluster(unsigned int cpu)
{
	unsigned int cluster = 0;
	smp_call_function_single(cpu, __get_current_cluster, &cluster, 1);
	return cluster;
}

static int get_current_cached_cluster(unsigned int cpu)
{
	return per_cpu(cpu_cur_cluster, cpu);
}

/* Validate policy frequency range */
static int vexpress_cpufreq_verify_policy(struct cpufreq_policy *policy)
{
	uint32_t cur_cluster = get_current_cached_cluster(policy->cpu);

	/* This call takes care of it all using freq_table */
	return cpufreq_frequency_table_verify(policy, freq_table[cur_cluster]);
}

/* Set clock frequency */
static int vexpress_cpufreq_set_target(struct cpufreq_policy *policy,
			     unsigned int target_freq, unsigned int relation)
{
	uint32_t cpu = policy->cpu;
	struct cpufreq_freqs freqs;
	uint32_t freq_tab_idx;
	uint32_t cur_cluster;
	int ret = 0;

	/* Read current clock rate */
	cur_cluster = get_current_cached_cluster(cpu);

	if (vexpress_spc_get_performance(cur_cluster, &freq_tab_idx))
		return -EIO;

	freqs.old = freq_table[cur_cluster][freq_tab_idx].frequency;

	/* Make sure that target_freq is within supported range */
	if (target_freq > policy->max)
		target_freq = policy->max;
	if (target_freq < policy->min)
		target_freq = policy->min;

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

	ret = vexpress_spc_set_performance(cur_cluster, freq_tab_idx);
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
static unsigned int vexpress_cpufreq_get(unsigned int cpu)
{
	uint32_t freq_tab_idx = 0;
	uint32_t cur_cluster = get_current_cached_cluster(cpu);

	/*
	 * Read current clock rate with vexpress_spc call
	 */
	if (vexpress_spc_get_performance(cur_cluster, &freq_tab_idx))
		return -EIO;

	return freq_table[cur_cluster][freq_tab_idx].frequency;
}

/* translate the integer array into cpufreq_frequency_table entries */
static inline void _cpufreq_copy_table_from_array(uint32_t *table,
			struct cpufreq_frequency_table *freq_table, int size)
{
	int i;
	for (i = 0; i < size; i++) {
		freq_table[i].index = i;
		freq_table[i].frequency =  table[i] / 1000; /* in kHZ */
	}
	freq_table[i].index = size;
	freq_table[i].frequency = CPUFREQ_TABLE_END;
}

static int vexpress_cpufreq_of_init(void)
{
	uint32_t cpu_opp_num;
	struct cpufreq_frequency_table *freqtable[VEXPRESS_MAX_CLUSTER];
	uint32_t *cpu_freqs;
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

		cpu_freqs = kzalloc(sizeof(uint32_t) * cpu_opp_num, GFP_KERNEL);
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
static int vexpress_cpufreq_init(struct cpufreq_policy *policy)
{
	int result = 0;
	uint32_t cur_cluster = get_current_cluster(policy->cpu);

	if (atomic_inc_return(&freq_table_users) == 1)
		result = vexpress_cpufreq_of_init();

	if (result) {
		atomic_dec_return(&freq_table_users);
		pr_err("CPUFreq - CPU %d failed to initialize\n", policy->cpu);
		return result;
	}

	result =
	    cpufreq_frequency_table_cpuinfo(policy, freq_table[cur_cluster]);
	if (result)
		return result;

	cpufreq_frequency_table_get_attr(freq_table[cur_cluster], policy->cpu);

	per_cpu(cpu_cur_cluster, policy->cpu) = cur_cluster;

	/* set default policy and cpuinfo */
	policy->min = policy->cpuinfo.min_freq;
	policy->max = policy->cpuinfo.max_freq;

	policy->cpuinfo.transition_latency = 1000000;	/* 1 ms assumed */
	policy->cur = vexpress_cpufreq_get(policy->cpu);

	cpumask_copy(policy->cpus, topology_core_cpumask(policy->cpu));
	cpumask_copy(policy->related_cpus, policy->cpus);

	pr_info("CPUFreq for CPU %d initialized\n", policy->cpu);
	return result;
}

/* Export freq_table to sysfs */
static struct freq_attr *vexpress_cpufreq_attr[] = {
	&cpufreq_freq_attr_scaling_available_freqs,
	NULL,
};

static struct cpufreq_driver vexpress_cpufreq_driver = {
	.flags	= CPUFREQ_STICKY,
	.verify	= vexpress_cpufreq_verify_policy,
	.target	= vexpress_cpufreq_set_target,
	.get	= vexpress_cpufreq_get,
	.init	= vexpress_cpufreq_init,
	.name	= "cpufreq_vexpress",
	.attr	= vexpress_cpufreq_attr,
};

static int __init vexpress_cpufreq_modinit(void)
{
	return cpufreq_register_driver(&vexpress_cpufreq_driver);
}

static void __exit vexpress_cpufreq_modexit(void)
{
	cpufreq_unregister_driver(&vexpress_cpufreq_driver);
}

MODULE_DESCRIPTION("cpufreq driver for ARM vexpress big.LITTLE platform");
MODULE_LICENSE("GPL");

module_init(vexpress_cpufreq_modinit);
module_exit(vexpress_cpufreq_modexit);
