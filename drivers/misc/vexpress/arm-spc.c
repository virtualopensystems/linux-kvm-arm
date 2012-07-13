/*
 * Serial Power Controller (SPC) support
 *
 * Copyright (C) 2012 ARM Ltd.
 * Author(s): Sudeep KarkadaNagesha <sudeep.karkadanagesha@arm.com>
 *            Achin Gupta           <achin.gupta@arm.com>
 *            Lorenzo Pieralisi     <lorenzo.pieralisi@arm.com>
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed "as is" WITHOUT ANY WARRANTY of any
 * kind, whether express or implied; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <linux/device.h>
#include <linux/delay.h>
#include <linux/err.h>
#include <linux/io.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/vexpress.h>

#define SNOOP_CTL_A15		0x404
#define SNOOP_CTL_A7		0x504
#define PERF_LVL_A15		0xB00
#define PERF_REQ_A15		0xB04
#define PERF_LVL_A7		0xB08
#define PERF_REQ_A7		0xB0c
#define COMMS			0xB10
#define COMMS_REQ		0xB14
#define PWC_STATUS		0xB18
#define PWC_FLAG		0xB1c
#define WAKE_INT_MASK		0xB24
#define WAKE_INT_RAW		0xB28
#define WAKE_INT_STAT		0xB2c
#define A15_PWRDN_EN		0xB30
#define A7_PWRDN_EN		0xB34
#define A15_A7_ISOLATE		0xB38
#define STANDBYWFI_STAT		0xB3c
#define A15_CACTIVE		0xB40
#define A15_PWRDNREQ		0xB44
#define A15_PWRDNACK		0xB48
#define A7_CACTIVE		0xB4c
#define A7_PWRDNREQ		0xB50
#define A7_PWRDNACK		0xB54
#define A15_RESET_HOLD		0xB58
#define A7_RESET_HOLD		0xB5c
#define A15_RESET_STAT		0xB60
#define A7_RESET_STAT		0xB64
#define A15_CONF		0x400
#define A7_CONF			0x500

#define DRIVER_NAME	"SPC"
#define TIME_OUT	100

struct vexpress_spc_drvdata {
	void __iomem *baseaddr;
	spinlock_t lock;
};

static struct vexpress_spc_drvdata *info;

/* SCC virtual address */
u32 vscc;

static inline int read_wait_to(void __iomem *reg, int status, int timeout)
{
	while (timeout-- && readl(reg) == status) {
		cpu_relax();
		udelay(2);
	}
	if (!timeout)
		return -EAGAIN;
	else
		return 0;
}

int vexpress_spc_get_performance(int cluster, int *perf)
{
	u32 perf_cfg_reg = 0;
	u32 a15_clusid = 0;
	int ret = 0;

	if (IS_ERR_OR_NULL(info))
		return -ENXIO;

	a15_clusid = readl_relaxed(info->baseaddr + A15_CONF) & 0xf;
	perf_cfg_reg = cluster != a15_clusid ? PERF_LVL_A7 : PERF_LVL_A15;

	spin_lock(&info->lock);
	*perf = readl(info->baseaddr + perf_cfg_reg);
	spin_unlock(&info->lock);

	return ret;

}
EXPORT_SYMBOL_GPL(vexpress_spc_get_performance);

int vexpress_spc_set_performance(int cluster, int perf)
{
	u32 perf_cfg_reg = 0;
	u32 perf_stat_reg = 0;
	u32 a15_clusid = 0;
	int ret = 0;

	if (IS_ERR_OR_NULL(info))
		return -ENXIO;

	a15_clusid = readl_relaxed(info->baseaddr + A15_CONF) & 0xf;
	perf_cfg_reg = cluster != a15_clusid ? PERF_LVL_A7 : PERF_LVL_A15;
	perf_stat_reg = cluster != a15_clusid ? PERF_REQ_A7 : PERF_REQ_A15;

	if (perf < 0 || perf > 7)
		return -EINVAL;

	spin_lock(&info->lock);
	writel(perf, info->baseaddr + perf_cfg_reg);
	if (read_wait_to(info->baseaddr + perf_stat_reg, 1, TIME_OUT))
		ret = -EAGAIN;
	spin_unlock(&info->lock);
	return ret;

}
EXPORT_SYMBOL_GPL(vexpress_spc_set_performance);

void vexpress_spc_set_wake_intr(u32 mask)
{
	if (!IS_ERR_OR_NULL(info))
		writel(mask & VEXPRESS_SPC_WAKE_INTR_MASK,
					info->baseaddr + WAKE_INT_MASK);
	return;
}
EXPORT_SYMBOL_GPL(vexpress_spc_set_wake_intr);

u32 vexpress_spc_get_wake_intr(int raw)
{
	u32 wake_intr_reg = raw ? WAKE_INT_RAW : WAKE_INT_STAT;

	if (!IS_ERR_OR_NULL(info))
		return readl(info->baseaddr + wake_intr_reg);
	else
		return 0;
}
EXPORT_SYMBOL_GPL(vexpress_spc_get_wake_intr);

void vexpress_spc_powerdown_enable(int cluster, int enable)
{
	u32 pwdrn_reg = 0;
	u32 a15_clusid = 0;

	if (!IS_ERR_OR_NULL(info)) {
		a15_clusid = readl_relaxed(info->baseaddr + A15_CONF) & 0xf;
		pwdrn_reg = cluster != a15_clusid ? A7_PWRDN_EN : A15_PWRDN_EN;
		writel(!!enable, info->baseaddr + pwdrn_reg);
	}
	return;
}
EXPORT_SYMBOL_GPL(vexpress_spc_powerdown_enable);

void vexpress_spc_adb400_pd_enable(int cluster, int enable)
{
	u32 pwdrn_reg = 0;
	u32 a15_clusid = 0;
	u32 val = enable ? 0xF : 0x0;	/* all adb bridges ?? */

	if (IS_ERR_OR_NULL(info))
		return;

	a15_clusid = readl_relaxed(info->baseaddr + A15_CONF) & 0xf;
	pwdrn_reg = cluster != a15_clusid ? A7_PWRDNREQ : A15_PWRDNREQ;

	spin_lock(&info->lock);
	writel(val, info->baseaddr + pwdrn_reg);
	spin_unlock(&info->lock);
	return;
}
EXPORT_SYMBOL_GPL(vexpress_spc_adb400_pd_enable);

void vexpress_scc_ctl_snoops(int cluster, int enable)
{
	u32 val;
	u32 snoop_reg = 0;
	u32 a15_clusid = 0;
	u32 or = 0;

	if (IS_ERR_OR_NULL(info))
		return;

	a15_clusid = readl_relaxed(info->baseaddr + A15_CONF) & 0xf;
	snoop_reg = cluster != a15_clusid ? SNOOP_CTL_A7 : SNOOP_CTL_A15;
	or = cluster != a15_clusid ? 0x2000 : 0x180;

	val = readl_relaxed(info->baseaddr + snoop_reg);
	if (enable) {
		or = ~or;
		val &= or;
	} else {
		val |= or;
	}
	writel_relaxed(val, info->baseaddr + snoop_reg);
}
EXPORT_SYMBOL_GPL(vexpress_scc_ctl_snoops);

void vexpress_spc_wfi_cpureset(int cluster, int cpu, int enable)
{
	u32 rsthold_reg, prst_shift;
	u32 val;
	u32 a15_clusid = 0;

	if (IS_ERR_OR_NULL(info))
		return;

	a15_clusid = readl_relaxed(info->baseaddr + A15_CONF) & 0xf;

	if (cluster != a15_clusid) {
		rsthold_reg = A7_RESET_HOLD;
		prst_shift = 3;
	} else {
		rsthold_reg = A15_RESET_HOLD;
		prst_shift = 2;
	}
	val = readl_relaxed(info->baseaddr + rsthold_reg);
	if (enable)
		val |= (1 << cpu);
	else
		val &= ~(1 << cpu);
	writel_relaxed(val, info->baseaddr + rsthold_reg);
	return;
}
EXPORT_SYMBOL_GPL(vexpress_spc_wfi_cpureset);

void vexpress_spc_wfi_cluster_reset(int cluster, int enable)
{
	u32 rsthold_reg, shift;
	u32 val;
	u32 a15_clusid = 0;

	if (IS_ERR_OR_NULL(info))
		return;

	a15_clusid = readl_relaxed(info->baseaddr + A15_CONF) & 0xf;

	if (cluster != a15_clusid) {
		rsthold_reg = A7_RESET_HOLD;
		shift = 6;
	} else {
		rsthold_reg = A15_RESET_HOLD;
		shift = 4;
	}
	spin_lock(&info->lock);
	val = readl(info->baseaddr + rsthold_reg);
	if (enable)
		val |= 1 << shift;
	else
		val &= ~(1 << shift);
	writel(val, info->baseaddr + rsthold_reg);
	spin_unlock(&info->lock);
	return;
}
EXPORT_SYMBOL_GPL(vexpress_spc_wfi_cluster_reset);

int vexpress_spc_wfi_cpustat(int cluster)
{
	u32 rststat_reg;
	u32 val;
	u32 a15_clusid = 0;

	if (IS_ERR_OR_NULL(info))
		return 0;

	a15_clusid = readl_relaxed(info->baseaddr + A15_CONF) & 0xf;
	rststat_reg = STANDBYWFI_STAT;

	val = readl_relaxed(info->baseaddr + rststat_reg);
	return cluster != a15_clusid ? ((val & 0x38) >> 3) : (val & 0x3);
}
EXPORT_SYMBOL_GPL(vexpress_spc_wfi_cpustat);


static int __devinit vexpress_spc_driver_probe(struct platform_device *pdev)
{
	struct resource *res;
	int ret = 0;

	info = kzalloc(sizeof(*info), GFP_KERNEL);
	if (!info) {
		dev_err(&pdev->dev, "unable to allocate mem\n");
		return -ENOMEM;
	}

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (!res) {
		dev_err(&pdev->dev, "No memory resource\n");
		ret = -EINVAL;
		goto mem_free;
	}

	if (!request_mem_region(res->start, resource_size(res),
				dev_name(&pdev->dev))) {
		dev_err(&pdev->dev, "address 0x%x in use\n", (u32) res->start);
		ret = -EBUSY;
		goto mem_free;
	}

	info->baseaddr = ioremap(res->start, resource_size(res));
	if (!info->baseaddr) {
		ret = -ENXIO;
		goto ioremap_err;
	}
	vscc = (u32) info->baseaddr;
	spin_lock_init(&info->lock);
	platform_set_drvdata(pdev, info);

	pr_info("vexpress_spc loaded at %p\n", info->baseaddr);
	return ret;

ioremap_err:
	release_region(res->start, resource_size(res));
mem_free:
	kfree(info);

	return ret;
}

static int __devexit vexpress_spc_driver_remove(struct platform_device *pdev)
{
	struct vexpress_spc_drvdata *info;
	struct resource *res = pdev->resource;

	info = platform_get_drvdata(pdev);
	iounmap(info->baseaddr);
	release_region(res->start, resource_size(res));
	kfree(info);

	return 0;
}

static const struct of_device_id arm_vexpress_spc_matches[] = {
	{.compatible = "arm,spc"},
	{},
};

static struct platform_driver vexpress_spc_platform_driver = {
	.driver = {
		   .owner = THIS_MODULE,
		   .name = DRIVER_NAME,
		   .of_match_table = arm_vexpress_spc_matches,
		   },
	.probe = vexpress_spc_driver_probe,
	.remove = vexpress_spc_driver_remove,
};

static int __init vexpress_spc_init(void)
{
	return platform_driver_register(&vexpress_spc_platform_driver);
}

static void __exit vexpress_spc_exit(void)
{
	platform_driver_unregister(&vexpress_spc_platform_driver);
}

arch_initcall(vexpress_spc_init);
module_exit(vexpress_spc_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Serial Power Controller (SPC) support");
