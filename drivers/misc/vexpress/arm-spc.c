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
#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/of_address.h>
#include <linux/of_irq.h>
#include <linux/slab.h>
#include <linux/semaphore.h>
#include <linux/vexpress.h>

#include <asm/cacheflush.h>
#include <asm/memory.h>
#include <asm/outercache.h>

#define SCC_CFGREG6             0x018
#define SCC_CFGREG19            0x120
#define SCC_CFGREG20            0x124
#define A15_CONF		0x400
#define SNOOP_CTL_A15		0x404
#define A7_CONF			0x500
#define SNOOP_CTL_A7		0x504
#define SYS_INFO		0x700
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
#define A15_BX_ADDR0            0xB68
#define SYS_CFG_WDATA		0xB70
#define SYS_CFG_RDATA		0xB74
#define A7_BX_ADDR0             0xB78
#define SPC_CONTROL		0xC00
#define SPC_LATENCY		0xC04
#define A15_PERFVAL_BASE	0xC10
#define A7_PERFVAL_BASE		0xC30

#define A15_STANDBYWFIL2_MSK    (1 << 2)
#define A7_STANDBYWFIL2_MSK     (1 << 6)
#define GBL_WAKEUP_INT_MSK      (0x3 << 10)

#define SYS_CFG_START		(1 << 31)
#define SYS_CFG_SCC		(6 << 20)
#define SYS_CFG_STAT		(14 << 20)

#define CLKF_SHIFT		16
#define CLKF_MASK		0x1FFF
#define CLKR_SHIFT		0
#define CLKR_MASK		0x3F
#define CLKOD_SHIFT		8
#define CLKOD_MASK		0xF

#define A15_PART_NO             0xF
#define A7_PART_NO              0x7

#define DRIVER_NAME	"SPC"
/*
 * Even though the SPC takes max 3-5 ms to complete any OPP/COMMS
 * operation, the operation could start just before jiffie is about
 * to be incremented. So setting timeout value of 20ms = 2jiffies@100Hz
 */
#define TIME_OUT_US	20000

#define MAX_OPPS	8
#define MAX_CLUSTERS	2

struct vexpress_spc_drvdata {
	void __iomem *baseaddr;
	uint32_t a15_clusid;
	int irq;
	uint32_t cur_rsp_mask;
	uint32_t cur_rsp_stat;
#define A15_OPP			0
#define A7_OPP			1
#define COMMS_OPP		2
#define STAT_COMPLETE(type)	((1 << 0) << (type << 2))
#define STAT_ERR(type)		((1 << 1) << (type << 2))
#define RESPONSE_MASK(type)	(STAT_COMPLETE(type) | STAT_ERR(type))
	struct semaphore lock;
	struct completion done;
	uint32_t freqs[MAX_CLUSTERS][MAX_OPPS];
};

static struct vexpress_spc_drvdata *info;

/* SCC virtual address */
u32 vscc;

u32 vexpress_spc_get_clusterid(int cpu_part_no)
{
	switch (cpu_part_no & 0xf) {
	case A15_PART_NO:
		return readl_relaxed(info->baseaddr + A15_CONF) & 0xf;
	case A7_PART_NO:
		return readl_relaxed(info->baseaddr + A7_CONF) & 0xf;
	default:
		BUG();
	}
}

EXPORT_SYMBOL_GPL(vexpress_spc_get_clusterid);

void vexpress_spc_write_bxaddr_reg(int cluster, int cpu, u32 val)
{
	void __iomem *baseaddr;

	if (IS_ERR_OR_NULL(info))
		return;

	if (cluster != info->a15_clusid)
		baseaddr = info->baseaddr + A7_BX_ADDR0 + (cpu << 2);
	else
		baseaddr = info->baseaddr + A15_BX_ADDR0 + (cpu << 2);

	writel_relaxed(val, baseaddr);
	dsb();
	while (val != readl_relaxed(baseaddr));

	return;
}

EXPORT_SYMBOL_GPL(vexpress_spc_write_bxaddr_reg);

int vexpress_spc_get_nb_cpus(int cluster)
{
	u32 val;

	if (IS_ERR_OR_NULL(info))
		return -ENXIO;

	val = readl_relaxed(info->baseaddr + SYS_INFO);
	val = (cluster != info->a15_clusid) ? (val >> 20) : (val >> 16);

	return (val & 0xf);
}

EXPORT_SYMBOL_GPL(vexpress_spc_get_nb_cpus);

int vexpress_spc_standbywfil2_status(int cluster)
{
	u32 standbywfi_stat;

	if (IS_ERR_OR_NULL(info))
		BUG();

	standbywfi_stat = readl_relaxed(info->baseaddr + STANDBYWFI_STAT);

	if (cluster != info->a15_clusid)
		return standbywfi_stat & A7_STANDBYWFIL2_MSK;
	else
		return standbywfi_stat & A15_STANDBYWFIL2_MSK;
}

EXPORT_SYMBOL_GPL(vexpress_spc_standbywfil2_status);

int vexpress_spc_standbywfi_status(int cluster, int cpu)
{
	u32 standbywfi_stat;

	if (IS_ERR_OR_NULL(info))
		BUG();

	standbywfi_stat = readl_relaxed(info->baseaddr + STANDBYWFI_STAT);

	if (cluster != info->a15_clusid)
		return standbywfi_stat & ((1 << cpu) << 3);
	else
		return standbywfi_stat & (1 << cpu);
}

EXPORT_SYMBOL_GPL(vexpress_spc_standbywfi_status);

u32 vexpress_spc_read_rststat_reg(int cluster)
{

	if (IS_ERR_OR_NULL(info))
		BUG();

	if (cluster != info->a15_clusid)
		return readl_relaxed(info->baseaddr + A7_RESET_STAT);
	else
		return readl_relaxed(info->baseaddr + A15_RESET_STAT);
}

EXPORT_SYMBOL_GPL(vexpress_spc_read_rststat_reg);

u32 vexpress_spc_read_rsthold_reg(int cluster)
{

	if (IS_ERR_OR_NULL(info))
		BUG();

	if (cluster != info->a15_clusid)
		return readl_relaxed(info->baseaddr + A7_RESET_HOLD);
	else
		return readl_relaxed(info->baseaddr + A15_RESET_HOLD);
}

EXPORT_SYMBOL_GPL(vexpress_spc_read_rsthold_reg);

void vexpress_spc_write_rsthold_reg(int cluster, u32 value)
{

	if (IS_ERR_OR_NULL(info))
		BUG();

	if (cluster != info->a15_clusid)
		writel_relaxed(value, info->baseaddr + A7_RESET_HOLD);
	else
		writel_relaxed(value, info->baseaddr + A15_RESET_HOLD);
}

EXPORT_SYMBOL_GPL(vexpress_spc_write_rsthold_reg);

int vexpress_spc_get_performance(int cluster, u32 *freq)
{
	u32 perf_cfg_reg = 0;
	int perf;

	if (IS_ERR_OR_NULL(info))
		return -ENXIO;

	perf_cfg_reg = cluster != info->a15_clusid ? PERF_LVL_A7 : PERF_LVL_A15;

	if (down_timeout(&info->lock, usecs_to_jiffies(TIME_OUT_US)))
		return -ETIME;

	perf = readl(info->baseaddr + perf_cfg_reg);

	*freq = info->freqs[cluster][perf];

	up(&info->lock);

	return 0;

}
EXPORT_SYMBOL_GPL(vexpress_spc_get_performance);

static int vexpress_spc_find_perf_index(int cluster, u32 freq)
{
	int idx;
	/* Hash function would be ideal, based on hashtable in v3.8?? */
	for (idx = 0; idx < MAX_OPPS; idx++)
		if (info->freqs[cluster][idx] == freq)
			break;
	return idx;
}

static int vexpress_spc_waitforcompletion(int req_type)
{
	int ret;

	if (!wait_for_completion_interruptible_timeout(&info->done,
					usecs_to_jiffies(TIME_OUT_US)))
		ret = -ETIMEDOUT;
	else
		ret = info->cur_rsp_stat & STAT_COMPLETE(req_type) ? 0 : -EIO;
	return ret;
}

int vexpress_spc_set_performance(int cluster, u32 freq)
{
	u32 perf_cfg_reg, perf_stat_reg;
	int ret, perf, req_type;

	if (IS_ERR_OR_NULL(info))
		return -ENXIO;

	if (cluster != info->a15_clusid) {
		req_type = A7_OPP;
		perf_cfg_reg = PERF_LVL_A7;
		perf_stat_reg = PERF_REQ_A7;
	} else {
		req_type = A15_OPP;
		perf_cfg_reg = PERF_LVL_A15;
		perf_stat_reg = PERF_REQ_A15;
	}

	perf = vexpress_spc_find_perf_index(cluster, freq);

	if (perf >= MAX_OPPS)
		return -EINVAL;

	if (down_timeout(&info->lock, usecs_to_jiffies(TIME_OUT_US)))
		return -ETIME;

	init_completion(&info->done);

	info->cur_rsp_mask = RESPONSE_MASK(req_type);

	writel(perf, info->baseaddr + perf_cfg_reg);

	ret = vexpress_spc_waitforcompletion(req_type);

	info->cur_rsp_mask = 0;

	up(&info->lock);

	return ret;
}
EXPORT_SYMBOL_GPL(vexpress_spc_set_performance);

int vexpress_spc_set_global_wakeup_intr(u32 set)
{
	u32 wake_int_mask_reg = 0;

	if (IS_ERR_OR_NULL(info))
		return -ENXIO;

	wake_int_mask_reg = readl(info->baseaddr + WAKE_INT_MASK);
	if (set)
		wake_int_mask_reg |= GBL_WAKEUP_INT_MSK;
	else
		wake_int_mask_reg &= ~GBL_WAKEUP_INT_MSK;

	vexpress_spc_set_wake_intr(wake_int_mask_reg);

	return 0;
}
EXPORT_SYMBOL_GPL(vexpress_spc_set_global_wakeup_intr);

int vexpress_spc_set_cpu_wakeup_irq(u32 cpu, u32 cluster, u32 set)
{
	u32 mask = 0;
	u32 wake_int_mask_reg = 0;

	if (IS_ERR_OR_NULL(info))
		return -ENXIO;

	mask = 1 << cpu;
	if (info->a15_clusid != cluster)
		mask <<= 4;

	wake_int_mask_reg = readl(info->baseaddr + WAKE_INT_MASK);
	if (set)
		wake_int_mask_reg |= mask;
	else
		wake_int_mask_reg &= ~mask;

	vexpress_spc_set_wake_intr(wake_int_mask_reg);

	return 0;
}
EXPORT_SYMBOL_GPL(vexpress_spc_set_cpu_wakeup_irq);

void vexpress_spc_set_wake_intr(u32 mask)
{
	if (!IS_ERR_OR_NULL(info)) {
		writel(mask & VEXPRESS_SPC_WAKE_INTR_MASK,
		       info->baseaddr + WAKE_INT_MASK);
		dsb();
		while ((mask & VEXPRESS_SPC_WAKE_INTR_MASK) !=
		       readl(info->baseaddr + WAKE_INT_MASK));
	}

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

	if (!IS_ERR_OR_NULL(info)) {
		pwdrn_reg = cluster != info->a15_clusid ? A7_PWRDN_EN : A15_PWRDN_EN;
		writel(!!enable, info->baseaddr + pwdrn_reg);
		dsb();
		while (readl(info->baseaddr + pwdrn_reg) != !!enable);
	}
	return;
}
EXPORT_SYMBOL_GPL(vexpress_spc_powerdown_enable);

void vexpress_spc_adb400_pd_enable(int cluster, int enable)
{
	u32 pwdrn_reg = 0;
	u32 val = enable ? 0xF : 0x0;	/* all adb bridges ?? */

	if (IS_ERR_OR_NULL(info))
		return;

	pwdrn_reg = cluster != info->a15_clusid ? A7_PWRDNREQ : A15_PWRDNREQ;

	writel(val, info->baseaddr + pwdrn_reg);
	return;
}
EXPORT_SYMBOL_GPL(vexpress_spc_adb400_pd_enable);

void vexpress_scc_ctl_snoops(int cluster, int enable)
{
	u32 val;
	u32 snoop_reg = 0;
	u32 or = 0;

	if (IS_ERR_OR_NULL(info))
		return;

	snoop_reg = cluster != info->a15_clusid ? SNOOP_CTL_A7 : SNOOP_CTL_A15;
	or = cluster != info->a15_clusid ? 0x2000 : 0x180;

	val = readl_relaxed(info->baseaddr + snoop_reg);
	if (enable) {
		or = ~or;
		val &= or;
	} else {
		val |= or;
		dsb();
		isb();
	}

	writel_relaxed(val, info->baseaddr + snoop_reg);
}
EXPORT_SYMBOL_GPL(vexpress_scc_ctl_snoops);

u32 vexpress_scc_read_rststat(int cluster)
{
	if (IS_ERR_OR_NULL(info))
		BUG();

	if (cluster != info->a15_clusid)
		return (readl_relaxed(info->baseaddr + SCC_CFGREG6) >> 16) & 0x7;
	else
		return (readl_relaxed(info->baseaddr + SCC_CFGREG6) >> 2) & 0x3;
}
EXPORT_SYMBOL_GPL(vexpress_scc_read_rststat);

void vexpress_spc_wfi_cpureset(int cluster, int cpu, int enable)
{
	u32 rsthold_reg, prst_shift;
	u32 val;

	if (IS_ERR_OR_NULL(info))
		return;

	if (cluster != info->a15_clusid) {
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

	if (IS_ERR_OR_NULL(info))
		return;

	if (cluster != info->a15_clusid) {
		rsthold_reg = A7_RESET_HOLD;
		shift = 6;
	} else {
		rsthold_reg = A15_RESET_HOLD;
		shift = 4;
	}
	val = readl(info->baseaddr + rsthold_reg);
	if (enable)
		val |= 1 << shift;
	else
		val &= ~(1 << shift);
	writel(val, info->baseaddr + rsthold_reg);
	return;
}
EXPORT_SYMBOL_GPL(vexpress_spc_wfi_cluster_reset);

int vexpress_spc_wfi_cpustat(int cluster)
{
	u32 rststat_reg;
	u32 val;

	if (IS_ERR_OR_NULL(info))
		return 0;

	rststat_reg = STANDBYWFI_STAT;

	val = readl_relaxed(info->baseaddr + rststat_reg);
	return cluster != info->a15_clusid ? ((val & 0x38) >> 3) : (val & 0x3);
}
EXPORT_SYMBOL_GPL(vexpress_spc_wfi_cpustat);

static bool vexpress_spc_loaded;

bool vexpress_spc_check_loaded(void)
{
	return vexpress_spc_loaded;
}
EXPORT_SYMBOL_GPL(vexpress_spc_check_loaded);

irqreturn_t vexpress_spc_irq_handler(int irq, void *data)
{
	struct vexpress_spc_drvdata *drv_data = data;
	uint32_t status = readl_relaxed(drv_data->baseaddr + PWC_STATUS);

	if (info->cur_rsp_mask & status) {
		info->cur_rsp_stat = status;
		complete(&drv_data->done);
	}

	return IRQ_HANDLED;
}

static int read_sys_cfg(int func, int offset, uint32_t *data)
{
	int ret;

	if (down_timeout(&info->lock, usecs_to_jiffies(TIME_OUT_US)))
		return -ETIME;

	init_completion(&info->done);

	info->cur_rsp_mask = RESPONSE_MASK(COMMS_OPP);

	/* Set the control value */
	writel(SYS_CFG_START | func | offset >> 2, info->baseaddr + COMMS);

	ret = vexpress_spc_waitforcompletion(COMMS_OPP);

	if (!ret)
		*data = readl(info->baseaddr + SYS_CFG_RDATA);

	info->cur_rsp_mask = 0;

	up(&info->lock);

	return ret;
}

/*
 * Based on the firmware documentation, this is always fixed to 20
 * All the 4 OSC: A15 PLL0/1, A7 PLL0/1 must be programmed same
 * values for both control and value registers.
 * This function uses A15 PLL 0 registers to compute multiple factor
 * F out = F in * (CLKF + 1) / ((CLKOD + 1) * (CLKR + 1))
 */
static inline int __get_mult_factor(void)
{
	int i_div, o_div, f_div;
	uint32_t tmp;

	tmp = readl(info->baseaddr + SCC_CFGREG19);
	f_div = (tmp >> CLKF_SHIFT) & CLKF_MASK;

	tmp = readl(info->baseaddr + SCC_CFGREG20);
	o_div = (tmp >> CLKOD_SHIFT) & CLKOD_MASK;
	i_div = (tmp >> CLKR_SHIFT) & CLKR_MASK;

	return (f_div + 1) / ((o_div + 1) * (i_div + 1));
}

static int vexpress_spc_populate_opps(uint32_t cluster)
{
	uint32_t data = 0, off, ret, j;
	int mult_fact = __get_mult_factor();

	off = cluster != info->a15_clusid ? A7_PERFVAL_BASE : A15_PERFVAL_BASE;
	for (j = 0; j < MAX_OPPS; j++, off += 4) {
		ret = read_sys_cfg(SYS_CFG_SCC, off, &data);
		if (!ret)
			info->freqs[cluster][j] = (data & 0xFFFFF) * mult_fact;
		else
			break;
	}

	return ret;
}

static int __init vexpress_spc_early_init(void)
{
	struct device_node *node = of_find_compatible_node(NULL, NULL,
							"arm,spc");

	info = kzalloc(sizeof(*info), GFP_KERNEL);
	if (!info) {
		pr_err("%s: unable to allocate mem\n", __func__);
		return -ENOMEM;
	}

	if (node)
		info->baseaddr = of_iomap(node, 0);

	if (WARN_ON(!info->baseaddr)) {
		kfree(info);
		return -EIO;
	}

	vscc = (u32) info->baseaddr;
	sema_init(&info->lock, 1);

	info->irq = irq_of_parse_and_map(node, 0);

	if (info->irq) {
		int ret;

		init_completion(&info->done);

		readl_relaxed(info->baseaddr + PWC_STATUS);

		ret = request_irq(info->irq, vexpress_spc_irq_handler,
			IRQF_DISABLED | IRQF_TRIGGER_HIGH | IRQF_ONESHOT, "arm-spc", info);
		if (ret) {
			pr_err("IRQ %d request failed \n", info->irq);
			iounmap(info->baseaddr);
			kfree(info);
			return -ENODEV;
		}
	}

	info->a15_clusid = readl_relaxed(info->baseaddr + A15_CONF) & 0xf;

	if (vexpress_spc_populate_opps(0) || vexpress_spc_populate_opps(1)) {
		if (info->irq)
			free_irq(info->irq, info);
		iounmap(info->baseaddr);
		kfree(info);
		pr_err("failed to build OPP table\n");
		return -ENODEV;
	}

	/*
	 * Multi-cluster systems may need this data when non-coherent, during
	 * cluster power-up/power-down. Make sure it reaches main memory:
	 */
	__cpuc_flush_dcache_area(info, sizeof *info);
	outer_clean_range(virt_to_phys(info), virt_to_phys(info + 1));

	pr_info("vexpress_spc loaded at %p\n", info->baseaddr);
	vexpress_spc_loaded = true;

	return 0;
}

early_initcall(vexpress_spc_early_init);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Serial Power Controller (SPC) support");
