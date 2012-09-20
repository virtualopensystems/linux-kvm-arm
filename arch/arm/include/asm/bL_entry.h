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

#ifndef __ASSEMBLY__

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

#endif /* ! __ASSEMBLY__ */
#endif
