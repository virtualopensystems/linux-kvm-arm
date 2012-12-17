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
#include <linux/irqflags.h>

#include <asm/bL_entry.h>
#include <asm/barrier.h>
#include <asm/proc-fns.h>
#include <asm/cacheflush.h>
#include <asm/idmap.h>

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

extern unsigned long bL_entry_early_pokes[BL_NR_CLUSTERS][BL_CPUS_PER_CLUSTER][2];

void bL_set_early_poke(unsigned cpu, unsigned cluster,
		unsigned long poke_phys_addr, unsigned long poke_val)
{
	unsigned long *poke = &bL_entry_early_pokes[cluster][cpu][0];
	poke[0] = poke_phys_addr;
	poke[1] = poke_val;
	smp_wmb();
	__cpuc_flush_dcache_area((void *)poke, 8);
	outer_clean_range(__pa(poke), __pa(poke + 2));
}

static const struct bL_platform_power_ops *platform_ops;

int __init bL_platform_power_register(const struct bL_platform_power_ops *ops)
{
	if (platform_ops)
		return -EBUSY;
	platform_ops = ops;
	return 0;
}

int bL_cpu_power_up(unsigned int cpu, unsigned int cluster)
{
	if (!platform_ops)
		return -EUNATCH;
	might_sleep();
	return platform_ops->power_up(cpu, cluster);
}

typedef void (*phys_reset_t)(unsigned long);

void bL_cpu_power_down(void)
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
	phys_reset(virt_to_phys(bL_entry_point));

	/* should never get here */
	BUG();
}

void bL_cpu_suspend(u64 expected_residency)
{
	phys_reset_t phys_reset;

	BUG_ON(!platform_ops);
	BUG_ON(!irqs_disabled());

	/* Very similar to bL_cpu_power_down() */
	setup_mm_for_reboot();
	platform_ops->suspend(expected_residency);
	phys_reset = (phys_reset_t)(unsigned long)virt_to_phys(cpu_reset);
	phys_reset(virt_to_phys(bL_entry_point));
	BUG();
}

int bL_cpu_powered_up(void)
{
	if (!platform_ops)
		return -EUNATCH;
	if (platform_ops->powered_up)
		platform_ops->powered_up();
	return 0;
}

unsigned long bL_sync_phys;
struct bL_sync_struct bL_sync;

static void __sync_range(volatile void *p, size_t size)
{
	char *_p = (char *)p;

	__cpuc_flush_dcache_area(_p, size);
	outer_flush_range(__pa(_p), __pa(_p + size));
	outer_sync();
}

#define sync_mem(ptr) __sync_range(ptr, sizeof *(ptr))

/*
 * __bL_cpu_going_down: Indicates that the cpu is being torn down.
 *    This must be called at the point of committing to teardown of a CPU.
 *    The CPU cache (SCTRL.C bit) is expected to still be active.
 */
void __bL_cpu_going_down(unsigned int cpu, unsigned int cluster)
{
	bL_sync.clusters[cluster].cpus[cpu].cpu = CPU_GOING_DOWN;
	sync_mem(&bL_sync.clusters[cluster].cpus[cpu].cpu);
}

/*
 * __bL_cpu_down: Indicates that cpu teardown is complete and that the
 *    cluster can be torn down without disrupting this CPU.
 *    To avoid deadlocks, this must be called before a CPU is powered down.
 *    The CPU cache (SCTRL.C bit) is expected to be off.
 */
void __bL_cpu_down(unsigned int cpu, unsigned int cluster)
{
	dsb();
	bL_sync.clusters[cluster].cpus[cpu].cpu = CPU_DOWN;
	sync_mem(&bL_sync.clusters[cluster].cpus[cpu].cpu);
	sev();
}

/*
 * __bL_outbound_leave_critical: Leave the cluster teardown critical section.
 * @state: the final state of the cluster:
 *     CLUSTER_UP: no destructive teardown was done and the cluster has been
 *         restored to the previous state (CPU cache still active); or
 *     CLUSTER_DOWN: the cluster has been torn-down, ready for power-off
 *         (CPU cache disabled).
 */
void __bL_outbound_leave_critical(unsigned int cluster, int state)
{
	dsb();
	bL_sync.clusters[cluster].cluster = state;
	sync_mem(&bL_sync.clusters[cluster].cluster);
	sev();
}

/*
 * __bL_outbound_enter_critical: Enter the cluster teardown critical section.
 * This function should be called by the last man, after local CPU teardown
 * is complete.  CPU cache expected to be active.
 *
 * Returns:
 *     false: the critical section was not entered because an inbound CPU was
 *         observed, or the cluster is already being set up;
 *     true: the critical section was entered: it is now safe to tear down the
 *         cluster.
 */
bool __bL_outbound_enter_critical(unsigned int cpu, unsigned int cluster)
{
	unsigned int i;
	struct bL_cluster_sync_struct *c = &bL_sync.clusters[cluster];

	/* Warn inbound CPUs that the cluster is being torn down: */
	c->cluster = CLUSTER_GOING_DOWN;
	sync_mem(&c->cluster);

	/* Back out if the inbound cluster is already in the critical region: */
	sync_mem(&c->inbound);
	if (c->inbound == INBOUND_COMING_UP)
		goto abort;

	/*
	 * Wait for all CPUs to get out of the GOING_DOWN state, so that local
	 * teardown is complete on each CPU before tearing down the cluster.
	 *
	 * If any CPU has been woken up again from the DOWN state, then we
	 * shouldn't be taking the cluster down at all: abort in that case.
	 */
	sync_mem(&c->cpus);
	for (i = 0; i < BL_CPUS_PER_CLUSTER; i++) {
		int cpustate;

		if (i == cpu)
			continue;

		while (1) {
			cpustate = c->cpus[i].cpu;
			if (cpustate != CPU_GOING_DOWN)
				break;

			wfe();
			sync_mem(&c->cpus[i].cpu);
		}

		switch (cpustate) {
		case CPU_DOWN:
			continue;

		default:
			goto abort;
		}
	}

	dsb();

	return true;

abort:
	__bL_outbound_leave_critical(cluster, CLUSTER_UP);
	return false;
}

int __bL_cluster_state(unsigned int cluster)
{
	sync_mem(&bL_sync.clusters[cluster].cluster);
	return bL_sync.clusters[cluster].cluster;
}

extern unsigned long bL_power_up_setup_phys;

int __init bL_cluster_sync_init(void (*power_up_setup)(void))
{
	unsigned int i, j, mpidr, this_cluster;

	BUILD_BUG_ON(BL_SYNC_CLUSTER_SIZE * BL_NR_CLUSTERS != sizeof bL_sync);
	bL_sync_phys = virt_to_phys(&bL_sync);
	BUG_ON(bL_sync_phys & (__CACHE_WRITEBACK_GRANULE - 1));
	sync_mem(&bL_sync_phys);

	/*
	 * Set initial CPU and cluster states.
	 * Only one cluster is assumed to be active at this point.
	 */
	for (i = 0; i < BL_NR_CLUSTERS; i++) {
		bL_sync.clusters[i].cluster = CLUSTER_DOWN;
		bL_sync.clusters[i].inbound = INBOUND_NOT_COMING_UP;
		for (j = 0; j < BL_CPUS_PER_CLUSTER; j++)
			bL_sync.clusters[i].cpus[j].cpu = CPU_DOWN;
	}
	asm ("mrc p15, 0, %0, c0, c0, 5" : "=r" (mpidr));
	this_cluster = (mpidr >> 8) & 0xf;
	for_each_online_cpu(i)
		bL_sync.clusters[this_cluster].cpus[i].cpu = CPU_UP;
	bL_sync.clusters[this_cluster].cluster = CLUSTER_UP;
	sync_mem(&bL_sync);

	if (power_up_setup) {
		bL_power_up_setup_phys = virt_to_phys(power_up_setup);
		sync_mem(&bL_power_up_setup_phys);
	}

	return 0;
}
