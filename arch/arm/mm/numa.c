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

cpumask_var_t *node_to_cpumask_map;
EXPORT_SYMBOL(node_to_cpumask_map);

void __init arm_numa_alloc_nodes(unsigned long max_low)
{
	int node;

	arm_numa_alloc_cpumask(max_low);

	for (node = 0; node < numa_node_count; node++) {
		phys_addr_t pa = memblock_alloc_base(sizeof(pg_data_t),
				L1_CACHE_BYTES, __pfn_to_phys(max_low));

		NODE_DATA(node) = __va(pa);
		memset(NODE_DATA(node), 0, sizeof(pg_data_t));
		NODE_DATA(node)->bdata = &bootmem_node_data[node];
	}
}

#ifdef CONFIG_NUMA

static unsigned int numa_use_topology;

static char *memcmdline __initdata;

int numa_cpu_lookup_table[NR_CPUS];
EXPORT_SYMBOL(numa_cpu_lookup_table);

static unsigned long pfn_starts[MAX_NUMNODES];

#ifdef CONFIG_DISCONTIGMEM
int pfn_to_nid(unsigned long pfn)
{
	int node;

	for (node = numa_node_count - 1; node >= 0; node--)
		if (pfn >= pfn_starts[node])
			return node;

	panic("NUMA: Unable to locate nid for %lX\n", pfn);
	return 0;
}
#endif

void __init arm_numa_alloc_cpumask(unsigned long max_low)
{
	size_t size = sizeof(cpumask_var_t) * numa_node_count;
	node_to_cpumask_map = __va(memblock_alloc_base(size,
				L1_CACHE_BYTES, __pfn_to_phys(max_low)));
	memset(node_to_cpumask_map, 0, size);
}

/*
 * Add a CPU to a NUMA node.
 * Default assignment policy is the cpu number modulo the number of nodes.
 *
 * We can also group CPUs via the topology_physical_package_id.
 * (if the user adds "usetopology" to the command line).
 * When we add CPU 0 (the boot CPU), it is always to node 0, as we don't have
 * the topology information at that time.
 * Subsequent CPUs get added based on the topology_physical_package_id.
 * To stop CPU0 being added to the same node as CPUs on a different cluster,
 * we subtract the topology_physical_package_id of node 0.
 *
 * This ensures that the TC2 has equivalent node configurations when booted
 * off the A15s or the A7s.
 */
static void add_cpu_to_node(int cpu)
{
	unsigned int node;
	unsigned int n0 = topology_physical_package_id(0);
	unsigned int nc = topology_physical_package_id(cpu);

	if (numa_use_topology)
		node = cpu ? (numa_node_count + nc - n0) % numa_node_count : 0;
	else
		node = cpu % numa_node_count;

	cpumask_set_cpu(cpu, node_to_cpumask_map[node]);
	numa_cpu_lookup_table[cpu] = node;
	pr_info("NUMA: Adding CPU %d to node %d\n", cpu, node);
}

static int __cpuinit numa_add_cpu(struct notifier_block *self,
				unsigned long action, void *cpu)
{
	if (action == CPU_ONLINE)
		add_cpu_to_node((int)cpu);

	return NOTIFY_OK;

}

static struct notifier_block __cpuinitdata numa_node_nb = {
	.notifier_call = numa_add_cpu,
	.priority = 1, /* Must run before sched domains notifier. */
};

/*
 * Split the available memory between the NUMA nodes.
 * We want all the pages mapped by a pmd to belong to the same node; as code,
 * such as the THP splitting code, assumes pmds are backed by contiguous
 * struct page *s. So we mask off the sizes with "rmask".
 *
 * By default, the memory is distributed roughly evenly between nodes.
 *
 * One can also specify requested node sizes on the command line, if
 * "memcmdline" is not NULL, we try to parse it as a size.
 *
 * We traverse memory blocks rather than the pfn addressable range to allow for
 * sparse memory configurations and memory holes.
 */
static void __init arm_numa_split_memblocks(void)
{
	const unsigned long rmask = ~((1UL << (PMD_SHIFT - PAGE_SHIFT)) - 1);
	unsigned int node;
	unsigned long pfnsrem = 0, pfnsblock, pfncurr, pfnend = 0;
	struct memblock_region *reg;

	for_each_memblock(memory, reg) {
		pfnend = memblock_region_memory_end_pfn(reg);
		pfnsrem += pfnend - memblock_region_memory_base_pfn(reg);
	}

	reg = memblock.memory.regions;
	pfnsblock = memblock_region_memory_end_pfn(reg)
		    - memblock_region_memory_base_pfn(reg);

	pfncurr = memblock_region_memory_base_pfn(reg);
	pfn_starts[0] = pfncurr;

	for (node = 0; node < numa_node_count - 1; node++) {
		unsigned long pfnsnode = pfnsrem / (numa_node_count - node)
					& rmask;

		if (memcmdline) {
			unsigned long nsize = __phys_to_pfn(
					     memparse(memcmdline, &memcmdline))
						& rmask;
			if (*memcmdline == ',')
				++memcmdline;

			if ((nsize > 0) && (nsize < pfnsrem))
				pfnsnode = nsize;
			else
				memcmdline = NULL;
		}

		while (pfnsnode > 0) {
			unsigned long pfnsset = min(pfnsnode, pfnsblock);

			pfncurr += pfnsset;

			pfnsblock -= pfnsset;
			pfnsrem -= pfnsset;
			pfnsnode -= pfnsset;

			if (pfnsblock == 0) {
				reg++;
				pfnsblock = memblock_region_memory_end_pfn(reg)
					    - memblock_region_memory_base_pfn(reg);
				pfncurr = memblock_region_memory_base_pfn(reg);
			}
		}

		pfn_starts[node + 1] = pfncurr;
	}

	for (node = 0; node < numa_node_count - 1; node++)
		memblock_set_node(__pfn_to_phys(pfn_starts[node]),
			__pfn_to_phys(pfn_starts[node + 1] - pfn_starts[node]),
			node);

	memblock_set_node(__pfn_to_phys(pfn_starts[node]),
		__pfn_to_phys(pfnend - pfn_starts[node]), node);

}

void __init arm_setup_nodes(unsigned long min, unsigned long max_high)
{
	int node;

	register_cpu_notifier(&numa_node_nb);
	arm_numa_split_memblocks();


	for (node = 0; node < numa_node_count; node++) {
		alloc_bootmem_cpumask_var(&node_to_cpumask_map[node]);
		node_set_online(node);
	}

	add_cpu_to_node(0);

}

static int __init early_numa(char *p)
{
	if (!p)
		return 0;

	p = strstr(p, "fake=");
	if (p) {
		int num_nodes = 0;
		int optres;

		p += strlen("fake=");
		optres = get_option(&p, &num_nodes);
		if ((optres == 0) || (optres == 3))
			return -EINVAL;

		if ((num_nodes > 0) && (num_nodes <= MAX_NUMNODES)) {
			pr_info("NUMA: setting up fake NUMA with %d nodes.\n",
				num_nodes);

			numa_node_count = num_nodes;
		} else {
			pr_info("NUMA: can't set up %d nodes for NUMA (MAX_NUMNODES = %d)\n",
				num_nodes, MAX_NUMNODES);
			return -EINVAL;
		}

		/*
		 * If a comma was specified after the number of nodes then subsequent
		 * numbers should be regarded as memory sizes for each node for as
		 * many nodes as are supplied.
		 */
		if (optres == 2)
			memcmdline = p;

		if (strstr(p, "usetopology")) {
			numa_use_topology = 1;
			pr_info("NUMA: using CPU topology to assign nodes.\n");
		} else
			pr_info("NUMA: NOT using CPU topology.\n");
	}

	return 0;
}
early_param("numa", early_numa);

#endif /* CONFIG_NUMA */
