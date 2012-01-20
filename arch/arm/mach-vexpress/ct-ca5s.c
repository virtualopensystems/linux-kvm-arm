/*
 * Versatile Express Cortex A5 Dual Core Tile (V2P-CA5s) Support
 */
#include <linux/init.h>
#include <linux/cpumask.h>
#include <linux/dma-mapping.h>
#include <linux/mm.h>
#include <linux/amba/bus.h>
#include <linux/amba/clcd.h>

#include <asm/cacheflush.h>
#include <asm/clkdev.h>
#include <asm/hardware/cache-l2x0.h>
#include <asm/hardware/gic.h>
#include <asm/smp_scu.h>
#include <asm/smp_twd.h>

#include <mach/clkdev.h>
#include <mach/ct-ca5s.h>

#include <asm/mach/map.h>

#include "core.h"

#include <mach/motherboard.h>

#include <plat/sched_clock.h>
#include <plat/clcd.h>

static struct map_desc ct_ca5s_io_desc[] __initdata = {
	{
		.virtual	= __MMIO_P2V(CT_CA5S_MPIC),
		.pfn		= __phys_to_pfn(CT_CA5S_MPIC),
		.length		= SZ_64K,
		.type		= MT_DEVICE,
	}, {
		.virtual	= __MMIO_P2V(CT_CA5S_L2CC),
		.pfn		= __phys_to_pfn(CT_CA5S_L2CC),
		.length		= SZ_4K,
		.type		= MT_DEVICE,
	},
};

#ifdef CONFIG_HAVE_ARM_TWD
static DEFINE_TWD_LOCAL_TIMER(twd_local_timer, A5_MPCORE_TWD, IRQ_LOCALTIMER);

static void __init ca5s_twd_init(void)
{
	int err = twd_local_timer_register(&twd_local_timer);
	if (err)
		pr_err("twd_local_timer_register failed %d\n", err);
}
#else
#define ca5s_twd_init()	do {} while(0)
#endif

static void __init ct_ca5s_init_early(void)
{
}

static void __init ct_ca5s_map_io(void)
{
	iotable_init(ct_ca5s_io_desc, ARRAY_SIZE(ct_ca5s_io_desc));
}

static void __init ct_ca5s_init_irq(void)
{
	gic_init(0, 29, MMIO_P2V(A5_MPCORE_GIC_DIST),
		 MMIO_P2V(A5_MPCORE_GIC_CPU));
}

static void __init ct_ca5s_timer_init(void)
{
	ca5s_twd_init();
	versatile_sched_clock_init(MMIO_P2V(V2M_SYS_24MHZ), 24000000);
}

static struct amba_device *ct_ca5s_amba_devs[] __initdata = {
};

static void __init ct_ca5s_init(void)
{
	int i;

#ifdef CONFIG_CACHE_L2X0
	void __iomem *l2x0_base = MMIO_P2V(CT_CA5S_L2CC);

	/* set RAM latencies to 1 cycle for this core tile. */
	writel(0, l2x0_base + L2X0_TAG_LATENCY_CTRL);
	writel(0, l2x0_base + L2X0_DATA_LATENCY_CTRL);

	l2x0_init(l2x0_base, 0x00400000, 0xfe0fffff);
#endif

	for (i = 0; i < ARRAY_SIZE(ct_ca5s_amba_devs); i++)
		amba_device_register(ct_ca5s_amba_devs[i], &iomem_resource);
}

#ifdef CONFIG_SMP
static void ct_ca5s_init_cpu_map(void)
{
	int i, ncores = scu_get_core_count(MMIO_P2V(A5_MPCORE_SCU));

	for (i = 0; i < ncores; ++i)
		set_cpu_possible(i, true);
}

static void ct_ca5s_smp_enable(unsigned int max_cpus)
{
	int i;
	for (i = 0; i < max_cpus; i++)
		set_cpu_present(i, true);

	scu_enable(MMIO_P2V(A5_MPCORE_SCU));
}
#endif

static struct ct_id ct_ca5s_ids[] = {
	{
		.id	= 0x12000225,
		.mask	= V2M_CT_ID_MASK,
	},
	{ },
};

struct ct_desc ct_ca5s_desc __initdata = {
	.id_table	= ct_ca5s_ids,
	.name		= "CA5s",
	.map_io		= ct_ca5s_map_io,
	.init_early	= ct_ca5s_init_early,
	.init_irq	= ct_ca5s_init_irq,
	.timer_init	= ct_ca5s_timer_init,
	.init_tile	= ct_ca5s_init,
#ifdef CONFIG_SMP
	.init_cpu_map	= ct_ca5s_init_cpu_map,
	.smp_enable	= ct_ca5s_smp_enable,
#endif
};
