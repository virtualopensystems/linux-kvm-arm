/*
 * Versatile Express V2M Motherboard Support
 */
#include <linux/export.h>
#include <linux/amba/mmci.h>
#include <linux/io.h>
#include <linux/init.h>
#include <linux/of_address.h>
#include <linux/of_irq.h>
#include <linux/of_platform.h>
#include <linux/of_fdt.h>
#include <linux/spinlock.h>
#include <linux/clkdev.h>
#include <linux/clk-provider.h>
#include <linux/mm.h>

#include <asm/system_misc.h>

#include "vexpress.h"

/*
 * Versatile Express System Registers.
 */
static const struct of_device_id v2m_sysregs_match[] __initconst = {
	{ .compatible = "arm,vexpress-sysreg", },
	{},
};

static void __iomem *v2m_sysregs_base __read_mostly;
static DEFINE_SPINLOCK(v2m_sysregs_cfg_lock);

static int __init v2m_sysregs_probe(void)
{
	struct device_node *node;

	node = of_find_matching_node(NULL, v2m_sysregs_match);
	if (!node)
		panic("unable to find compatible v2m sysregs node in dtb\n");

	v2m_sysregs_base = of_iomap(node, 0);
	if (!v2m_sysregs_base)
		panic("unable to map v2m system registers\n");

	of_node_put(node);

	return 0;
}

static int v2m_sysregs_cfg_write(u32 devfn, u32 data)
{
	u32 val;

	printk("%s: writing %08x to %08x\n", __func__, data, devfn);

	devfn |= SYS_CFG_START | SYS_CFG_WRITE;

	spin_lock(&v2m_sysregs_cfg_lock);
	val = readl(v2m_sysregs_base + V2M_SYS_CFGSTAT);
	writel(val & ~SYS_CFG_COMPLETE, v2m_sysregs_base + V2M_SYS_CFGSTAT);

	writel(data, v2m_sysregs_base + V2M_SYS_CFGDATA);
	writel(devfn, v2m_sysregs_base + V2M_SYS_CFGCTRL);

	do {
		val = readl(v2m_sysregs_base + V2M_SYS_CFGSTAT);
	} while (val == 0);
	spin_unlock(&v2m_sysregs_cfg_lock);

	return !!(val & SYS_CFG_ERR);
}

/*
 * Clocks.
 */
static unsigned long v2m_osc_recalc_rate(struct clk_hw *hw,
					 unsigned long parent_rate)
{
	return 0;
}

static long v2m_osc_round_rate(struct clk_hw *hw, unsigned long rate,
			       unsigned long *parent_rate)
{
	return rate;
}

static int v2m_osc1_set_rate(struct clk_hw *clk_hw, unsigned long rate,
			     unsigned long prate)
{
	return v2m_sysregs_cfg_write(SYS_CFG_OSC | SYS_CFG_SITE_MB | 1, rate);
}

static const struct clk_ops osc1_clk_ops = {
	.recalc_rate	= v2m_osc_recalc_rate,
	.round_rate	= v2m_osc_round_rate,
	.set_rate	= v2m_osc1_set_rate,
};

static struct clk_init_data osc1_clk_init_data = {
	.name	= "osc1_clk",
	.ops	= &osc1_clk_ops,
	.flags	= CLK_IS_ROOT,
};

static struct clk_hw osc1_clk_hw = {
	.init = &osc1_clk_init_data,
};

static void __init v2m_clk_init(void)
{
	struct clk *clk;

	clk = clk_register_fixed_rate(NULL, "apb_pclk", NULL, CLK_IS_ROOT, 0);
	WARN_ON(clk_register_clkdev(clk, "abp_pclk", NULL));

	clk = clk_register(NULL, &osc1_clk_hw);
	WARN_ON(clk_register_clkdev(clk, NULL, "mb:clcd"));

	clk = clk_register_fixed_rate(NULL, "osc2_clk", NULL, CLK_IS_ROOT,
				      24000000);
	WARN_ON(clk_register_clkdev(clk, NULL, "mb:mmci"));
	WARN_ON(clk_register_clkdev(clk, NULL, "1c060000.kmi"));
	WARN_ON(clk_register_clkdev(clk, NULL, "1c070000.kmi"));
	WARN_ON(clk_register_clkdev(clk, NULL, "1c090000.uart"));
	WARN_ON(clk_register_clkdev(clk, NULL, "1c0a0000.uart"));
	WARN_ON(clk_register_clkdev(clk, NULL, "1c0b0000.uart"));
	WARN_ON(clk_register_clkdev(clk, NULL, "1c0c0000.uart"));

	clk = clk_register_fixed_rate(NULL, "v2m_ref_clk", NULL, CLK_IS_ROOT,
				      32768);
	WARN_ON(clk_register_clkdev(clk, NULL, "1c0f0000.wdt"));
}

/*
 * Platform data definitions.
 */
static unsigned int v2m_mmci_status(struct device *dev)
{
	return readl(v2m_sysregs_base + V2M_SYS_MCI) & (1 << 0);
}

static struct mmci_platform_data v2m_mmci_data = {
	.ocr_mask	= MMC_VDD_32_33|MMC_VDD_33_34,
	.status		= v2m_mmci_status,
};

static struct of_dev_auxdata v2m_dt_auxdata_lookup[] __initdata = {
	OF_DEV_AUXDATA("arm,primecell", V2M_MMCI, "mb:mmci", &v2m_mmci_data),
	{}
};

static void v2m_power_off(void)
{
	if (v2m_sysregs_cfg_write(SYS_CFG_SHUTDOWN | SYS_CFG_SITE_MB, 0))
		pr_emerg("Unable to shutdown\n");
}

static void v2m_restart(const char *cmd)
{
	if (v2m_sysregs_cfg_write(SYS_CFG_REBOOT | SYS_CFG_SITE_MB, 0))
		pr_emerg("Unable to reboot\n");
}

static const char *vexpress_dt_match[] __initdata = {
	"arm,vexpress",
	NULL,
};

static int __init v2m_probe(void)
{
	if (!of_flat_dt_match(of_get_flat_dt_root(), vexpress_dt_match))
		return 0;

	v2m_sysregs_probe();

	v2m_clk_init();

	of_platform_populate(NULL, of_default_bus_match_table,
			     v2m_dt_auxdata_lookup, NULL);

	pm_power_off = v2m_power_off;
	pm_restart = v2m_restart;

	return 0;
}
arch_initcall(v2m_probe);
