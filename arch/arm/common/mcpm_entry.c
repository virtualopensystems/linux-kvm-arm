/*
 * arch/arm/common/mcpm_entry.c -- entry point for multi-cluster PM
 *
 * Created by:  Nicolas Pitre, March 2012
 * Copyright:   (C) 2012-2013  Linaro Limited
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/irqflags.h>

#include <asm/mcpm_entry.h>
#include <asm/barrier.h>
#include <asm/proc-fns.h>
#include <asm/cacheflush.h>
#include <asm/idmap.h>
#include <asm/cputype.h>

extern volatile unsigned long mcpm_entry_vectors[MAX_NR_CLUSTERS][MAX_CPUS_PER_CLUSTER];

void mcpm_set_entry_vector(unsigned cpu, unsigned cluster, void *ptr)
{
	unsigned long val = ptr ? virt_to_phys(ptr) : 0;
	mcpm_entry_vectors[cluster][cpu] = val;
	__cpuc_flush_dcache_area((void *)&mcpm_entry_vectors[cluster][cpu], 4);
	outer_clean_range(__pa(&mcpm_entry_vectors[cluster][cpu]),
			  __pa(&mcpm_entry_vectors[cluster][cpu + 1]));
}

static const struct mcpm_platform_ops *platform_ops;

int __init mcpm_platform_register(const struct mcpm_platform_ops *ops)
{
	if (platform_ops)
		return -EBUSY;
	platform_ops = ops;
	return 0;
}

int mcpm_cpu_power_up(unsigned int cpu, unsigned int cluster)
{
	if (!platform_ops)
		return -EUNATCH; /* try not to shadow power_up errors */
	might_sleep();
	return platform_ops->power_up(cpu, cluster);
}

typedef void (*phys_reset_t)(unsigned long);

void mcpm_cpu_power_down(void)
{
	phys_reset_t phys_reset;

	BUG_ON(!platform_ops);
	BUG_ON(!irqs_disabled());

	/*
	 * Do this before calling into the power_down method,
	 * as it might not always be safe to do afterwards.
	 */
	setup_mm_for_reboot();

	platform_ops->power_down();

	/*
	 * It is possible for a power_up request to happen concurrently
	 * with a power_down request for the same CPU. In this case the
	 * power_down method might not be able to actually enter a
	 * powered down state with the WFI instruction if the power_up
	 * method has removed the required reset condition.  The
	 * power_down method is then allowed to return. We must perform
	 * a re-entry in the kernel as if the power_up method just had
	 * deasserted reset on the CPU.
	 *
	 * To simplify race issues, the platform specific implementation
	 * must accommodate for the possibility of unordered calls to
	 * power_down and power_up with a usage count. Therefore, if a
	 * call to power_up is issued for a CPU that is not down, then
	 * the next call to power_down must not attempt a full shutdown
	 * but only do the minimum (normally disabling L1 cache and CPU
	 * coherency) and return just as if a concurrent power_up request
	 * had happened as described above.
	 */

	phys_reset = (phys_reset_t)(unsigned long)virt_to_phys(cpu_reset);
	phys_reset(virt_to_phys(mcpm_entry_point));

	/* should never get here */
	BUG();
}

void mcpm_cpu_suspend(u64 expected_residency)
{
	phys_reset_t phys_reset;

	BUG_ON(!platform_ops);
	BUG_ON(!irqs_disabled());

	/* Very similar to mcpm_cpu_power_down() */
	setup_mm_for_reboot();
	platform_ops->suspend(expected_residency);
	phys_reset = (phys_reset_t)(unsigned long)virt_to_phys(cpu_reset);
	phys_reset(virt_to_phys(mcpm_entry_point));
	BUG();
}

int mcpm_cpu_powered_up(void)
{
	if (!platform_ops)
		return -EUNATCH;
	if (platform_ops->powered_up)
		platform_ops->powered_up();
	return 0;
}

struct sync_struct mcpm_sync;

/*
 * There is no __cpuc_clean_dcache_area but we use it anyway for
 * code intent clarity, and alias it to __cpuc_flush_dcache_area.
 */
#define __cpuc_clean_dcache_area __cpuc_flush_dcache_area

/*
 * Ensure preceding writes to *p by this CPU are visible to
 * subsequent reads by other CPUs:
 */
static void __sync_range_w(volatile void *p, size_t size)
{
	char *_p = (char *)p;

	__cpuc_clean_dcache_area(_p, size);
	outer_clean_range(__pa(_p), __pa(_p + size));
}

/*
 * Ensure preceding writes to *p by other CPUs are visible to
 * subsequent reads by this CPU.  We must be careful not to
 * discard data simultaneously written by another CPU, hence the
 * usage of flush rather than invalidate operations.
 */
static void __sync_range_r(volatile void *p, size_t size)
{
	char *_p = (char *)p;

#ifdef CONFIG_OUTER_CACHE
	if (outer_cache.flush_range) {
		/*
		 * Ensure dirty data migrated from other CPUs into our cache
		 * are cleaned out safely before the outer cache is cleaned:
		 */
		__cpuc_clean_dcache_area(_p, size);

		/* Clean and invalidate stale data for *p from outer ... */
		outer_flush_range(__pa(_p), __pa(_p + size));
	}
#endif

	/* ... and inner cache: */
	__cpuc_flush_dcache_area(_p, size);
}

#define sync_w(ptr) __sync_range_w(ptr, sizeof *(ptr))
#define sync_r(ptr) __sync_range_r(ptr, sizeof *(ptr))

/*
 * __mcpm_cpu_going_down: Indicates that the cpu is being torn down.
 *    This must be called at the point of committing to teardown of a CPU.
 *    The CPU cache (SCTRL.C bit) is expected to still be active.
 */
void __mcpm_cpu_going_down(unsigned int cpu, unsigned int cluster)
{
	mcpm_sync.clusters[cluster].cpus[cpu].cpu = CPU_GOING_DOWN;
	sync_w(&mcpm_sync.clusters[cluster].cpus[cpu].cpu);
}

/*
 * __mcpm_cpu_down: Indicates that cpu teardown is complete and that the
 *    cluster can be torn down without disrupting this CPU.
 *    To avoid deadlocks, this must be called before a CPU is powered down.
 *    The CPU cache (SCTRL.C bit) is expected to be off.
 */
void __mcpm_cpu_down(unsigned int cpu, unsigned int cluster)
{
	dmb();
	mcpm_sync.clusters[cluster].cpus[cpu].cpu = CPU_DOWN;
	sync_w(&mcpm_sync.clusters[cluster].cpus[cpu].cpu);
	dsb_sev();
}

/*
 * __mcpm_outbound_leave_critical: Leave the cluster teardown critical section.
 * @state: the final state of the cluster:
 *     CLUSTER_UP: no destructive teardown was done and the cluster has been
 *         restored to the previous state (CPU cache still active); or
 *     CLUSTER_DOWN: the cluster has been torn-down, ready for power-off
 *         (CPU cache disabled).
 */
void __mcpm_outbound_leave_critical(unsigned int cluster, int state)
{
	dmb();
	mcpm_sync.clusters[cluster].cluster = state;
	sync_w(&mcpm_sync.clusters[cluster].cluster);
	dsb_sev();
}

/*
 * __mcpm_outbound_enter_critical: Enter the cluster teardown critical section.
 * This function should be called by the last man, after local CPU teardown
 * is complete.  CPU cache expected to be active.
 *
 * Returns:
 *     false: the critical section was not entered because an inbound CPU was
 *         observed, or the cluster is already being set up;
 *     true: the critical section was entered: it is now safe to tear down the
 *         cluster.
 */
bool __mcpm_outbound_enter_critical(unsigned int cpu, unsigned int cluster)
{
	unsigned int i;
	struct mcpm_sync_struct *c = &mcpm_sync.clusters[cluster];

	/* Warn inbound CPUs that the cluster is being torn down: */
	c->cluster = CLUSTER_GOING_DOWN;
	sync_w(&c->cluster);

	/* Back out if the inbound cluster is already in the critical region: */
	sync_r(&c->inbound);
	if (c->inbound == INBOUND_COMING_UP)
		goto abort;

	/*
	 * Wait for all CPUs to get out of the GOING_DOWN state, so that local
	 * teardown is complete on each CPU before tearing down the cluster.
	 *
	 * If any CPU has been woken up again from the DOWN state, then we
	 * shouldn't be taking the cluster down at all: abort in that case.
	 */
	sync_r(&c->cpus);
	for (i = 0; i < MAX_CPUS_PER_CLUSTER; i++) {
		int cpustate;

		if (i == cpu)
			continue;

		while (1) {
			cpustate = c->cpus[i].cpu;
			if (cpustate != CPU_GOING_DOWN)
				break;

			wfe();
			sync_r(&c->cpus[i].cpu);
		}

		switch (cpustate) {
		case CPU_DOWN:
			continue;

		default:
			goto abort;
		}
	}

	return true;

abort:
	__mcpm_outbound_leave_critical(cluster, CLUSTER_UP);
	return false;
}

int __mcpm_cluster_state(unsigned int cluster)
{
	sync_r(&mcpm_sync.clusters[cluster].cluster);
	return mcpm_sync.clusters[cluster].cluster;
}

extern unsigned long mcpm_power_up_setup_phys;

int __init mcpm_sync_init(
	void (*power_up_setup)(unsigned int affinity_level))
{
	unsigned int i, j, mpidr, this_cluster;

	BUILD_BUG_ON(MCPM_SYNC_CLUSTER_SIZE * MAX_NR_CLUSTERS != sizeof mcpm_sync);
	BUG_ON((unsigned long)&mcpm_sync & (__CACHE_WRITEBACK_GRANULE - 1));

	/*
	 * Set initial CPU and cluster states.
	 * Only one cluster is assumed to be active at this point.
	 */
	for (i = 0; i < MAX_NR_CLUSTERS; i++) {
		mcpm_sync.clusters[i].cluster = CLUSTER_DOWN;
		mcpm_sync.clusters[i].inbound = INBOUND_NOT_COMING_UP;
		for (j = 0; j < MAX_CPUS_PER_CLUSTER; j++)
			mcpm_sync.clusters[i].cpus[j].cpu = CPU_DOWN;
	}
	mpidr = read_cpuid_mpidr();
	this_cluster = MPIDR_AFFINITY_LEVEL(mpidr, 1);
	for_each_online_cpu(i)
		mcpm_sync.clusters[this_cluster].cpus[i].cpu = CPU_UP;
	mcpm_sync.clusters[this_cluster].cluster = CLUSTER_UP;
	sync_w(&mcpm_sync);

	if (power_up_setup) {
		mcpm_power_up_setup_phys = virt_to_phys(power_up_setup);
		sync_w(&mcpm_power_up_setup_phys);
	}

	return 0;
}
