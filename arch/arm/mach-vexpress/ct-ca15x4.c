/*
 * Versatile Express Core Tile Cortex A15x4 Support
 */
#include <linux/init.h>
#include <linux/cpumask.h>
#include <linux/dma-mapping.h>
#include <linux/mm.h>
#include <linux/amba/bus.h>
#include <linux/amba/clcd.h>

#include <asm/cacheflush.h>
#include <asm/clkdev.h>
#include <asm/hardware/gic.h>

#include <mach/clkdev.h>
#include <mach/ct-ca15x4.h>

#include <asm/mach/map.h>

#include "core.h"

#include <mach/motherboard.h>

#include <plat/clcd.h>

static struct map_desc ct_ca15x4_io_desc[] __initdata = {
	{
		.virtual	= __MMIO_P2V(CT_CA15X4_MPIC),
		.pfn		= __phys_to_pfn(CT_CA15X4_MPIC),
		.length		= SZ_64K,
		.type		= MT_DEVICE,
	},
};

static void __init ct_ca15x4_map_io(void)
{
	iotable_init(ct_ca15x4_io_desc, ARRAY_SIZE(ct_ca15x4_io_desc));
}

static void __init ct_ca15x4_init_early(void)
{
}

static void __init ct_ca15x4_init_irq(void)
{
	gic_init(0, 29, MMIO_P2V(A15_MPCORE_GIC_DIST),
		 MMIO_P2V(A15_MPCORE_GIC_CPU));
}

static void __init ct_ca15x4_timer_init(void)
{
}

static int ct_ca15x4_has_clcdc;

/*
 * Core tile CLCD controller.
 * FIXME: This will be replaced with the HDLCD when available.
 */
static void ct_ca15x4_clcd_enable(struct clcd_fb *fb)
{
	v2m_cfg_write(SYS_CFG_MUXFPGA | SYS_CFG_SITE_DB1, 0);
	v2m_cfg_write(SYS_CFG_DVIMODE | SYS_CFG_SITE_DB1, 2);
}

static int ct_ca15x4_clcd_setup(struct clcd_fb *fb)
{
	unsigned long framesize = 1024 * 768 * 2;

	if (!ct_ca15x4_has_clcdc)
		return -ENODEV;

	fb->panel = versatile_clcd_get_panel("XVGA");
	if (!fb->panel)
		return -EINVAL;

	return versatile_clcd_setup_dma(fb, framesize);
}

static struct clcd_board ct_ca15x4_clcd_data = {
	.name		= "CT-CA15X4",
	.caps		= CLCD_CAP_5551 | CLCD_CAP_565,
	.check		= clcdfb_check,
	.decode		= clcdfb_decode,
	.enable		= ct_ca15x4_clcd_enable,
	.setup		= ct_ca15x4_clcd_setup,
	.mmap		= versatile_clcd_mmap_dma,
	.remove		= versatile_clcd_remove_dma,
};

static AMBA_DEVICE(ct_clcd, "ct:clcd", CT_CA15X4_CLCDC, &ct_ca15x4_clcd_data);

static struct amba_device *ct_ca15x4_clcd_probe(void)
{
	struct amba_device *clcd_device = NULL;

	/* FIXME:
	 * The model currently doesn't have *anything* in the tile
	 * CLCD space so probing results in an external abort.
	 */
	u32 periphid;
	void __iomem *clcd_addr = NULL;/*ioremap(CT_CA15X4_CLCDC, SZ_4K);*/

	if (clcd_addr) {
		periphid = readl(clcd_addr + 0xfe0) & 0xff;
		periphid |= (readl(clcd_addr + 0xfe4) & 0xf) << 8;
		if (periphid == 0x111)
			clcd_device = &ct_clcd_device;
		iounmap(clcd_addr);
	}

	return clcd_device;
}


static struct amba_device *ct_ca15x4_amba_devs[] __initdata = {
};

static void ct_ca15x4_init(void)
{
	int i;
	struct amba_device *clcd_device = ct_ca15x4_clcd_probe();

	if (clcd_device)
		amba_device_register(clcd_device, &iomem_resource);

	for (i = 0; i < ARRAY_SIZE(ct_ca15x4_amba_devs); i++)
		amba_device_register(ct_ca15x4_amba_devs[i], &iomem_resource);
}

#ifdef CONFIG_SMP
static void ct_ca15x4_init_cpu_map(void)
{
	unsigned int i, ncores;

	asm volatile("mrc p15, 1, %0, c9, c0, 2\n" : "=r" (ncores));
	ncores = ((ncores >> 24) & 3) + 1;

	for (i = 0; i < ncores; i++)
		set_cpu_possible(i, true);
}

static void ct_ca15x4_smp_enable(unsigned int max_cpus)
{
	int i;

	for (i = 0; i < max_cpus; i++)
		set_cpu_present(i, true);
}
#endif

struct ct_desc ct_ca15x4_desc __initdata = {
	.id		= V2M_CT_ID_CA15,
	.name		= "CA15x4",
	.map_io		= ct_ca15x4_map_io,
	.init_early	= ct_ca15x4_init_early,
	.init_irq	= ct_ca15x4_init_irq,
	.timer_init	= ct_ca15x4_timer_init,
	.init_tile	= ct_ca15x4_init,
#ifdef CONFIG_SMP
	.init_cpu_map	= ct_ca15x4_init_cpu_map,
	.smp_enable	= ct_ca15x4_smp_enable,
#endif
};
