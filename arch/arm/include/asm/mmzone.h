/*
 * Discontiguous memory and NUMA support, based on the PowerPC implementation.
 *
 * Copyright (C) 2012 ARM Limited
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#ifndef __ASM_ARM_MMZONE_H_
#define __ASM_ARM_MMZONE_H_
#ifdef __KERNEL__

#include <linux/cpumask.h>

#ifdef CONFIG_NUMA_ALLOC_NODES
#define NODE_DATA(nid)		(node_data[nid])
extern void __init arm_numa_alloc_nodes(unsigned long max_low);
extern struct pglist_data *node_data[];
#else
#define arm_numa_alloc_nodes(_mlow)	do {} while (0)
#endif

#define	pfn_to_nid(pfn)		(0)

#endif /* __KERNEL__ */
#endif /* __ASM_ARM_MMZONE_H_ */
