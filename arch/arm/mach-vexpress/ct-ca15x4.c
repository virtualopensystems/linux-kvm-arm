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

static void __init ct_ca15x4_init_irq(void)
{
	gic_init(0, 29, MMIO_P2V(A15_MPCORE_GIC_DIST),
		 MMIO_P2V(A15_MPCORE_GIC_CPU));
}

static int ct_ca15x4_has_clcdc;

static struct clcd_panel xvga_panel = {
	.mode		= {
		.name		= "XVGA",
		.refresh	= 60,
		.xres		= 1024,
		.yres		= 768,
		.pixclock	= 15384,
		.left_margin	= 168,
		.right_margin	= 8,
		.upper_margin	= 29,
		.lower_margin	= 3,
		.hsync_len	= 144,
		.vsync_len	= 6,
		.sync		= 0,
		.vmode		= FB_VMODE_NONINTERLACED,
	},
	.width		= -1,
	.height		= -1,
	.tim2		= TIM2_BCD | TIM2_IPC,
	.cntl		= CNTL_LCDTFT | CNTL_BGR | CNTL_LCDVCOMP(1),
	.bpp		= 16,
};

/*
 * Motherboard CLCD controller.
 */
static void v2m_clcd_enable(struct clcd_fb *fb)
{
	v2m_cfg_write(SYS_CFG_MUXFPGA | SYS_CFG_SITE_MB, 0);
	/* FIXME: Deadlocks the model
	   v2m_cfg_write(SYS_CFG_DVIMODE | SYS_CFG_SITE_MB, 2);*/
}

static int v2m_clcd_setup(struct clcd_fb *fb)
{
	unsigned long framesize = 1024 * 768 * 2;

	if (ct_ca15x4_has_clcdc)
		return -ENODEV;

	fb->panel = &xvga_panel;
	fb->fb.screen_base = ioremap_wc(V2M_VIDEO_SRAM, framesize);

	if (!fb->fb.screen_base) {
		printk(KERN_ERR "CLCD: unable to map frame buffer\n");
		return -ENOMEM;
	}

	fb->fb.fix.smem_start = V2M_VIDEO_SRAM;
	fb->fb.fix.smem_len = framesize;

	return 0;
}

static int v2m_clcd_mmap(struct clcd_fb *fb, struct vm_area_struct *vma)
{
	unsigned long off, user_size, kern_size;

	off = vma->vm_pgoff << PAGE_SHIFT;
	user_size = vma->vm_end - vma->vm_start;
	kern_size = fb->fb.fix.smem_len;

	if (off >= kern_size || user_size > (kern_size - off))
		return -ENXIO;

	return remap_pfn_range(vma, vma->vm_start,
			__phys_to_pfn(fb->fb.fix.smem_start) + vma->vm_pgoff,
			user_size,
			pgprot_writecombine(vma->vm_page_prot));
}

static void v2m_clcd_remove(struct clcd_fb *fb)
{
	iounmap(fb->fb.screen_base);
}


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
	dma_addr_t dma;

	if (!ct_ca15x4_has_clcdc)
		return -ENODEV;

	fb->panel = &xvga_panel;
	fb->fb.screen_base = dma_alloc_writecombine(&fb->dev->dev,
						    framesize,
						    &dma,
						    GFP_KERNEL);

	if (!fb->fb.screen_base) {
		printk(KERN_ERR "CLCD: unable to map frame buffer\n");
		return -ENOMEM;
	}

	fb->fb.fix.smem_start = dma;
	fb->fb.fix.smem_len = framesize;

	return 0;
}

static int ct_ca15x4_clcd_mmap(struct clcd_fb *fb, struct vm_area_struct *vma)
{
	return dma_mmap_writecombine(&fb->dev->dev, vma,
				     fb->fb.screen_base,
				     fb->fb.fix.smem_start,
				     fb->fb.fix.smem_len);
}

static void ct_ca15x4_clcd_remove(struct clcd_fb *fb)
{
	dma_free_writecombine(&fb->dev->dev, fb->fb.fix.smem_len,
			      fb->fb.screen_base, fb->fb.fix.smem_start);
}

static struct clcd_board ct_ca15x4_clcd_data = {
	.name		= "CT-CA15X4",
	.check		= clcdfb_check,
	.decode		= clcdfb_decode,
	.enable		= ct_ca15x4_clcd_enable,
	.setup		= ct_ca15x4_clcd_setup,
	.mmap		= ct_ca15x4_clcd_mmap,
	.remove		= ct_ca15x4_clcd_remove,
};

static struct clcd_board v2m_clcd_data = {
	.name		= "V2M",
	.check		= clcdfb_check,
	.decode		= clcdfb_decode,
	.enable		= v2m_clcd_enable,
	.setup		= v2m_clcd_setup,
	.mmap		= v2m_clcd_mmap,
	.remove		= v2m_clcd_remove,
};

static AMBA_DEVICE(ct_clcd, "ct:clcd", CT_CA15X4_CLCDC, &ct_ca15x4_clcd_data);
static AMBA_DEVICE(v2m_clcd, "mb:clcd", V2M_CLCD, &v2m_clcd_data);

static struct amba_device *ct_ca15x4_clcd_probe(void)
{
	struct amba_device *clcd_device = &v2m_clcd_device;

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

static void ct_ca15x4_init(void) {
	int i;

	amba_device_register(ct_ca15x4_clcd_probe(), &iomem_resource);

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
	.init_irq	= ct_ca15x4_init_irq,
	.init_tile	= ct_ca15x4_init,
#ifdef CONFIG_SMP
	.init_cpu_map	= ct_ca15x4_init_cpu_map,
	.smp_enable	= ct_ca15x4_smp_enable,
#endif
};
