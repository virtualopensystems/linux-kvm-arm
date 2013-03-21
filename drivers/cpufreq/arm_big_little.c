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

#include <linux/clk.h>
#include <linux/cpufreq.h>
#include <linux/cpumask.h>
#include <linux/export.h>
#include <linux/of_platform.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <asm/topology.h>
#include "arm_big_little.h"

#define MAX_CLUSTERS	2

static struct cpufreq_arm_bL_ops *arm_bL_ops;
static struct clk *clk[MAX_CLUSTERS];
static struct cpufreq_frequency_table *freq_table[MAX_CLUSTERS];
static atomic_t cluster_usage[MAX_CLUSTERS] = {ATOMIC_INIT(0), ATOMIC_INIT(0)};

/*
 * Functions to get the current status.
 *
 * Beware that the cluster for another CPU may change unexpectedly.
 */
static int cpu_to_cluster(int cpu)
{
	return topology_physical_package_id(cpu);
}

static unsigned int bL_cpufreq_get(unsigned int cpu)
{
	u32 cur_cluster = cpu_to_cluster(cpu);

	return clk_get_rate(clk[cur_cluster]) / 1000;
}

/* Validate policy frequency range */
static int bL_cpufreq_verify_policy(struct cpufreq_policy *policy)
{
	u32 cur_cluster = cpu_to_cluster(policy->cpu);

	/* This call takes care of it all using freq_table */
	return cpufreq_frequency_table_verify(policy, freq_table[cur_cluster]);
}

/* Set clock frequency */
static int bL_cpufreq_set_target(struct cpufreq_policy *policy,
		unsigned int target_freq, unsigned int relation)
{
	struct cpufreq_freqs freqs;
	u32 cpu = policy->cpu, freq_tab_idx, cur_cluster;
	int ret = 0;

	/* ASSUMPTION: The cpu can't be hotplugged in this function */
	cur_cluster = cpu_to_cluster(policy->cpu);

	freqs.old = bL_cpufreq_get(policy->cpu);

	/* Determine valid target frequency using freq_table */
	cpufreq_frequency_table_target(policy, freq_table[cur_cluster],
			target_freq, relation, &freq_tab_idx);
	freqs.new = freq_table[cur_cluster][freq_tab_idx].frequency;

	freqs.cpu = policy->cpu;

	pr_debug("%s: cpu: %d, cluster: %d, oldfreq: %d, target freq: %d, new freq: %d\n",
			__func__, cpu, cur_cluster, freqs.old, target_freq,
			freqs.new);

	if (freqs.old == freqs.new)
		return 0;

	for_each_cpu(freqs.cpu, policy->cpus)
		cpufreq_notify_transition(&freqs, CPUFREQ_PRECHANGE);

	ret = clk_set_rate(clk[cur_cluster], freqs.new * 1000);
	if (ret) {
		pr_err("clk_set_rate failed: %d\n", ret);
		return ret;
	}

	policy->cur = freqs.new;

	for_each_cpu(freqs.cpu, policy->cpus)
		cpufreq_notify_transition(&freqs, CPUFREQ_POSTCHANGE);

	return ret;
}

/* translate the integer array into cpufreq_frequency_table entries */
struct cpufreq_frequency_table *
arm_bL_copy_table_from_array(unsigned int *table, int count)
{
	int i;

	struct cpufreq_frequency_table *freq_table;

	pr_debug("%s: table: %p, count: %d\n", __func__, table, count);

	freq_table = kmalloc(sizeof(*freq_table) * (count + 1), GFP_KERNEL);
	if (!freq_table)
		return NULL;

	for (i = 0; i < count; i++) {
		pr_debug("%s: index: %d, freq: %d\n", __func__, i, table[i]);
		freq_table[i].index = i;
		freq_table[i].frequency = table[i]; /* in kHZ */
	}

	freq_table[i].index = count;
	freq_table[i].frequency = CPUFREQ_TABLE_END;

	return freq_table;
}
EXPORT_SYMBOL_GPL(arm_bL_copy_table_from_array);

void arm_bL_free_freq_table(u32 cluster)
{
	pr_debug("%s: free freq table\n", __func__);

	kfree(freq_table[cluster]);
}
EXPORT_SYMBOL_GPL(arm_bL_free_freq_table);

static void put_cluster_clk_and_freq_table(u32 cluster)
{
	if (!atomic_dec_return(&cluster_usage[cluster])) {
		clk_put(clk[cluster]);
		clk[cluster] = NULL;
		arm_bL_ops->put_freq_tbl(cluster);
		freq_table[cluster] = NULL;
		pr_debug("%s: cluster: %d\n", __func__, cluster);
	}
}

static int get_cluster_clk_and_freq_table(u32 cluster)
{
	char name[9] = "cluster";
	int count;

	if (atomic_inc_return(&cluster_usage[cluster]) != 1)
		return 0;

	freq_table[cluster] = arm_bL_ops->get_freq_tbl(cluster, &count);
	if (!freq_table[cluster])
		goto atomic_dec;

	name[7] = cluster + '0';
	clk[cluster] = clk_get(NULL, name);
	if (!IS_ERR_OR_NULL(clk[cluster])) {
		pr_debug("%s: clk: %p & freq table: %p, cluster: %d\n",
				__func__, clk[cluster], freq_table[cluster],
				cluster);
		return 0;
	}

	arm_bL_ops->put_freq_tbl(cluster);

atomic_dec:
	atomic_dec(&cluster_usage[cluster]);
	pr_err("%s: Failed to get data for cluster: %d\n", __func__, cluster);
	return -ENODATA;
}

/* Per-CPU initialization */
static int bL_cpufreq_init(struct cpufreq_policy *policy)
{
	u32 cur_cluster = cpu_to_cluster(policy->cpu);
	int result;

	result = get_cluster_clk_and_freq_table(cur_cluster);
	if (result)
		return result;

	result = cpufreq_frequency_table_cpuinfo(policy,
			freq_table[cur_cluster]);
	if (result) {
		pr_err("CPU %d, cluster: %d invalid freq table\n", policy->cpu,
				cur_cluster);
		put_cluster_clk_and_freq_table(cur_cluster);
		return result;
	}

	cpufreq_frequency_table_get_attr(freq_table[cur_cluster], policy->cpu);

	policy->cpuinfo.transition_latency = 1000000;	/* 1 ms assumed */
	policy->cur = bL_cpufreq_get(policy->cpu);

	cpumask_copy(policy->cpus, topology_core_cpumask(policy->cpu));
	cpumask_copy(policy->related_cpus, policy->cpus);

	pr_info("CPU %d initialized\n", policy->cpu);
	return 0;
}

static int bL_cpufreq_exit(struct cpufreq_policy *policy)
{
	put_cluster_clk_and_freq_table(cpu_to_cluster(policy->cpu));
	pr_debug("%s: Exited, cpu: %d\n", __func__, policy->cpu);

	return 0;
}

/* Export freq_table to sysfs */
static struct freq_attr *bL_cpufreq_attr[] = {
	&cpufreq_freq_attr_scaling_available_freqs,
	NULL,
};

static struct cpufreq_driver bL_cpufreq_driver = {
	.name	= "arm-big-little",
	.flags	= CPUFREQ_STICKY,
	.verify	= bL_cpufreq_verify_policy,
	.target	= bL_cpufreq_set_target,
	.get	= bL_cpufreq_get,
	.init	= bL_cpufreq_init,
	.exit	= bL_cpufreq_exit,
	.attr	= bL_cpufreq_attr,
};

int bL_cpufreq_register(struct cpufreq_arm_bL_ops *ops)
{
	int ret;

	if (arm_bL_ops) {
		pr_debug("%s: Already registered: %s, exiting\n", __func__,
				arm_bL_ops->name);
		return -EBUSY;
	}

	if (!ops || !strlen(ops->name) || !ops->get_freq_tbl) {
		pr_err("%s: Invalid arm_bL_ops, exiting\n", __func__);
		return -ENODEV;
	}

	arm_bL_ops = ops;

	ret = cpufreq_register_driver(&bL_cpufreq_driver);
	if (ret) {
		pr_info("%s: Failed registering platform driver: %s, err: %d\n",
				__func__, ops->name, ret);
		arm_bL_ops = NULL;
	} else {
		pr_info("%s: Registered platform driver: %s\n", __func__,
				ops->name);
	}

	return ret;
}
EXPORT_SYMBOL_GPL(bL_cpufreq_register);

void bL_cpufreq_unregister(struct cpufreq_arm_bL_ops *ops)
{
	if (arm_bL_ops != ops) {
		pr_info("%s: Registered with: %s, can't unregister, exiting\n",
				__func__, arm_bL_ops->name);
	}

	cpufreq_unregister_driver(&bL_cpufreq_driver);
	pr_info("%s: Un-registered platform driver: %s\n", __func__,
			arm_bL_ops->name);
	arm_bL_ops = NULL;
}
EXPORT_SYMBOL_GPL(bL_cpufreq_unregister);
