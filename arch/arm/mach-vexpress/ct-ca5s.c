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

static void __init ct_ca5s_map_io(void)
{
#ifdef CONFIG_HAVE_ARM_TWD
	twd_base = MMIO_P2V(A5_MPCORE_TWD);
#endif
	iotable_init(ct_ca5s_io_desc, ARRAY_SIZE(ct_ca5s_io_desc));
}

static void __init ct_ca5s_init_early(void)
{
}

static void __init ct_ca5s_init_irq(void)
{
	gic_init(0, 29, MMIO_P2V(A5_MPCORE_GIC_DIST),
		 MMIO_P2V(A5_MPCORE_GIC_CPU));
}

/*
 * Motherboard CLCD controller.
 */
static void v2m_clcd_enable(struct clcd_fb *fb)
{
	v2m_cfg_write(SYS_CFG_MUXFPGA | SYS_CFG_SITE_MB, 0);
	v2m_cfg_write(SYS_CFG_DVIMODE | SYS_CFG_SITE_MB, 2);
}

static int v2m_clcd_setup(struct clcd_fb *fb)
{
	unsigned long framesize = 640 * 480 * 2;

	fb->panel = versatile_clcd_get_panel("VGA");
	if (!fb->panel)
		return -EINVAL;

	return versatile_clcd_setup_dma(fb, framesize);
}

static struct clcd_board v2m_clcd_data = {
	.name		= "V2M",
	.caps		= CLCD_CAP_5551 | CLCD_CAP_565,
	.check		= clcdfb_check,
	.decode		= clcdfb_decode,
	.enable		= v2m_clcd_enable,
	.setup		= v2m_clcd_setup,
	.mmap		= versatile_clcd_mmap_dma,
	.remove		= versatile_clcd_remove_dma,
};

static AMBA_DEVICE(v2m_clcd, "mb:clcd", V2M_CLCD, &v2m_clcd_data);

static struct amba_device *ct_ca5s_amba_devs[] __initdata = {
	&v2m_clcd_device,
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

struct ct_desc ct_ca5s_desc __initdata = {
	.id		= V2M_CT_ID_CA5S,
	.name		= "CA5s",
	.map_io		= ct_ca5s_map_io,
	.init_early	= ct_ca5s_init_early,
	.init_irq	= ct_ca5s_init_irq,
	.init_tile	= ct_ca5s_init,
#ifdef CONFIG_SMP
	.init_cpu_map	= ct_ca5s_init_cpu_map,
	.smp_enable	= ct_ca5s_smp_enable,
#endif
};
