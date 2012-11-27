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

#include <linux/export.h>
#include <linux/nodemask.h>
#include <linux/bootmem.h>
#include <linux/mm.h>
#include <linux/mmzone.h>
#include <linux/node.h>
#include <linux/cpu.h>
#include <linux/memblock.h>

#include <asm/string.h>
#include <asm/mmzone.h>
#include <asm/setup.h>

struct pglist_data *node_data[MAX_NUMNODES];
EXPORT_SYMBOL(node_data);

static unsigned int numa_node_count = 1;

void __init arm_numa_alloc_nodes(unsigned long max_low)
{
	int node;

	for (node = 0; node < numa_node_count; node++) {
		phys_addr_t pa = memblock_alloc_base(sizeof(pg_data_t),
				L1_CACHE_BYTES, __pfn_to_phys(max_low));

		NODE_DATA(node) = __va(pa);
		memset(NODE_DATA(node), 0, sizeof(pg_data_t));
		NODE_DATA(node)->bdata = &bootmem_node_data[node];
	}
}
