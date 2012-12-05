/*
 * arch/arm/include/asm/bL_entry.h
 *
 * Created by:  Nicolas Pitre, April 2012
 * Copyright:   (C) 2012  Linaro Limited
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef BL_ENTRY_H
#define BL_ENTRY_H

#define BL_CPUS_PER_CLUSTER	4
#define BL_NR_CLUSTERS		2

/* Definitions for bL_cluster_sync_struct */
#define CPU_DOWN		0x11
#define CPU_COMING_UP		0x12
#define CPU_UP			0x13
#define CPU_GOING_DOWN		0x14

#define CLUSTER_DOWN		0x21
#define CLUSTER_UP		0x22
#define CLUSTER_GOING_DOWN	0x23

#define INBOUND_NOT_COMING_UP	0x31
#define INBOUND_COMING_UP	0x32

/* This is a complete guess. */
#define __CACHE_WRITEBACK_ORDER	6
#define __CACHE_WRITEBACK_GRANULE (1 << __CACHE_WRITEBACK_ORDER)

/* Offsets for the bL_cluster_sync_struct members, for use in asm: */
#define BL_SYNC_CLUSTER_CPUS	0
#define BL_SYNC_CPU_SIZE	__CACHE_WRITEBACK_GRANULE
#define BL_SYNC_CLUSTER_CLUSTER \
	(BL_SYNC_CLUSTER_CPUS + BL_SYNC_CPU_SIZE * BL_CPUS_PER_CLUSTER)
#define BL_SYNC_CLUSTER_INBOUND \
	(BL_SYNC_CLUSTER_CLUSTER + __CACHE_WRITEBACK_GRANULE)
#define BL_SYNC_CLUSTER_SIZE \
	(BL_SYNC_CLUSTER_INBOUND + __CACHE_WRITEBACK_GRANULE)

#ifndef __ASSEMBLY__

#include <linux/types.h>

/*
 * Platform specific code should use this symbol to set up secondary
 * entry location for processors to use when released from reset.
 */
extern void bL_entry_point(void);

/*
 * This is used to indicate where the given CPU from given cluster should
 * branch once it is ready to re-enter the kernel using ptr, or NULL if it
 * should be gated.  A gated CPU is held in a WFE loop until its vector
 * becomes non NULL.
 */
void bL_set_entry_vector(unsigned cpu, unsigned cluster, void *ptr);

/*
 * This sets an early poke i.e a value to be poked into some address
 * from very early assembly code before the CPU is ungated.  The
 * address must be physical, and if 0 then nothing will happen.
 */
void bL_set_early_poke(unsigned cpu, unsigned cluster,
		       unsigned long poke_phys_addr, unsigned long poke_val);

/*
 * CPU/cluster power operations API for higher subsystems to use.
 */

/**
 * bL_cpu_power_up - make given CPU in given cluster runable
 *
 * @cpu: CPU number within given cluster
 * @cluster: cluster number for the CPU
 *
 * The identified CPU is brought out of reset.  If the cluster was powered
 * down then it is brought up as well, taking care not to let the other CPUs
 * in the cluster run, and ensuring appropriate cluster setup.
 *
 * Caller must ensure the appropriate entry vector is initialized with
 * bL_set_entry_vector() prior to calling this.
 *
 * This must be called in a sleepable context.  However, the implementation
 * is strongly encouraged to return early and let the operation happen
 * asynchronously, especially when significant delays are expected.
 *
 * If the operation cannot be performed then an error code is returned.
 */
int bL_cpu_power_up(unsigned int cpu, unsigned int cluster);

/**
 * bL_cpu_power_down - power the calling CPU down
 *
 * The calling CPU is powered down.
 *
 * If this CPU is found to be the "last man standing" in the cluster
 * then the cluster is prepared for power-down too.
 *
 * This must be called with interrupts disabled.
 *
 * This does not return.  Re-entry in the kernel is expected via
 * bL_entry_point.
 */
void bL_cpu_power_down(void);

/**
 * bL_cpu_suspend - bring the calling CPU in a suspended state
 *
 * @expected_residency: duration in microseconds the CPU is expected
 *			to remain suspended, or 0 if unknown/infinity.
 *
 * The calling CPU is suspended.  The expected residency argument is used
 * as a hint by the platform specific backend to implement the appropriate
 * sleep state level according to the knowledge it has on wake-up latency
 * for the given hardware.
 *
 * If this CPU is found to be the "last man standing" in the cluster
 * then the cluster may be prepared for power-down too, if the expected
 * residency makes it worthwhile.
 *
 * This must be called with interrupts disabled.
 *
 * This does not return.  Re-entry in the kernel is expected via
 * bL_entry_point.
 */
void bL_cpu_suspend(u64 expected_residency);

/**
 * bL_cpu_powered_up - housekeeping workafter a CPU has been powered up
 *
 * This lets the platform specific backend code perform needed housekeeping
 * work.  This must be called by the newly activated CPU as soon as it is
 * fully operational in kernel space, before it enables interrupts.
 *
 * If the operation cannot be performed then an error code is returned.
 */
int bL_cpu_powered_up(void);

/*
 * Platform specific methods used in the implementation of the above API.
 */
struct bL_platform_power_ops {
	int (*power_up)(unsigned int cpu, unsigned int cluster);
	void (*power_down)(void);
	void (*suspend)(u64);
	void (*powered_up)(void);
};

/**
 * bL_platform_power_register - register platform specific power methods
 *
 * @ops: bL_platform_power_ops structure to register
 *
 * An error is returned if the registration has been done previously.
 */
int __init bL_platform_power_register(const struct bL_platform_power_ops *ops);

/* Synchronisation structures for coordinating safe cluster setup/teardown: */

/*
 * When modifying this structure, make sure you update the BL_SYNC_ defines
 * to match.
 */
struct bL_cluster_sync_struct {
	/* individual CPU states */
	struct {
		volatile s8 cpu __aligned(__CACHE_WRITEBACK_GRANULE);
	} cpus[BL_CPUS_PER_CLUSTER];

	/* cluster state */
	volatile s8 cluster __aligned(__CACHE_WRITEBACK_GRANULE);

	/* inbound-side state */
	volatile s8 inbound __aligned(__CACHE_WRITEBACK_GRANULE);
};

struct bL_sync_struct {
	struct bL_cluster_sync_struct clusters[BL_NR_CLUSTERS];
};

extern unsigned long bL_sync_phys;	/* physical address of *bL_sync */

void __bL_cpu_going_down(unsigned int cpu, unsigned int cluster);
void __bL_cpu_down(unsigned int cpu, unsigned int cluster);
void __bL_outbound_leave_critical(unsigned int cluster, int state);
bool __bL_outbound_enter_critical(unsigned int this_cpu, unsigned int cluster);
int __bL_cluster_state(unsigned int cluster);

int __init bL_cluster_sync_init(void (*power_up_setup)(void));

#endif /* ! __ASSEMBLY__ */
#endif
