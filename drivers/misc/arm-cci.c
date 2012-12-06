/*
 * CCI support
 *
 * Copyright (C) 2012 ARM Ltd.
 * Author: Lorenzo Pieralisi <lorenzo.pieralisi@arm.com>
 *
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
#include <linux/io.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include <linux/arm-cci.h>

#include <asm/cacheflush.h>
#include <asm/memory.h>
#include <asm/outercache.h>

#include <asm/irq_regs.h>
#include <asm/pmu.h>

#define CCI400_PMCR                   0x0100
#define CCI400_EAG_OFFSET             0x4000
#define CCI400_KF_OFFSET              0x5000

#define DRIVER_NAME	"CCI"
struct cci_drvdata {
	void __iomem *baseaddr;
	spinlock_t lock;
};

static struct cci_drvdata *info;

#ifdef CONFIG_HW_PERF_EVENTS

#define CCI400_PMU_CYCLE_CNTR_BASE    0x9000
#define CCI400_PMU_CNTR_BASE(idx)     (CCI400_PMU_CYCLE_CNTR_BASE + (idx) * 0x1000)

#define CCI400_PMCR_CEN          0x00000001
#define CCI400_PMCR_RST          0x00000002
#define CCI400_PMCR_CCR          0x00000004
#define CCI400_PMCR_CCD          0x00000008
#define CCI400_PMCR_EX           0x00000010
#define CCI400_PMCR_DP           0x00000020
#define CCI400_PMCR_NCNT_MASK    0x0000F800
#define CCI400_PMCR_NCNT_SHIFT   11

#define CCI400_PMU_EVT_SEL       0x000
#define CCI400_PMU_CNTR          0x004
#define CCI400_PMU_CNTR_CTRL     0x008
#define CCI400_PMU_OVERFLOW      0x00C

#define CCI400_PMU_OVERFLOW_FLAG 1

enum cci400_perf_events {
	CCI400_PMU_CYCLES = 0xFF
};

#define CCI400_PMU_EVENT_MASK   0xff
#define CCI400_PMU_EVENT_SOURCE(event) ((event >> 5) & 0x7)
#define CCI400_PMU_EVENT_CODE(event) (event & 0x1f)

#define CCI400_PMU_EVENT_SOURCE_S0 0
#define CCI400_PMU_EVENT_SOURCE_S4 4
#define CCI400_PMU_EVENT_SOURCE_M0 5
#define CCI400_PMU_EVENT_SOURCE_M2 7

#define CCI400_PMU_EVENT_SLAVE_MIN 0x0
#define CCI400_PMU_EVENT_SLAVE_MAX 0x13

#define CCI400_PMU_EVENT_MASTER_MIN 0x14
#define CCI400_PMU_EVENT_MASTER_MAX 0x1A

#define CCI400_PMU_MAX_HW_EVENTS 5   /* CCI PMU has 4 counters + 1 cycle counter */

#define CCI400_PMU_CYCLE_COUNTER_IDX 0
#define CCI400_PMU_COUNTER0_IDX      1
#define CCI400_PMU_COUNTER_LAST(cci_pmu) (CCI400_PMU_CYCLE_COUNTER_IDX + cci_pmu->num_events - 1)


static struct perf_event *events[CCI400_PMU_MAX_HW_EVENTS];
static unsigned long used_mask[BITS_TO_LONGS(CCI400_PMU_MAX_HW_EVENTS)];
static struct pmu_hw_events cci_hw_events = {
	.events    = events,
	.used_mask = used_mask,
};

static int cci_pmu_validate_hw_event(u8 hw_event)
{
	u8 ev_source = CCI400_PMU_EVENT_SOURCE(hw_event);
	u8 ev_code = CCI400_PMU_EVENT_CODE(hw_event);

	if (ev_source <= CCI400_PMU_EVENT_SOURCE_S4 &&
	    ev_code <= CCI400_PMU_EVENT_SLAVE_MAX)
			return hw_event;
	else if (CCI400_PMU_EVENT_SOURCE_M0 <= ev_source &&
		   ev_source <= CCI400_PMU_EVENT_SOURCE_M2 &&
		   CCI400_PMU_EVENT_MASTER_MIN <= ev_code &&
		    ev_code <= CCI400_PMU_EVENT_MASTER_MAX)
			return hw_event;

	return -EINVAL;
}

static inline int cci_pmu_counter_is_valid(struct arm_pmu *cci_pmu, int idx)
{
	return CCI400_PMU_CYCLE_COUNTER_IDX <= idx &&
		idx <= CCI400_PMU_COUNTER_LAST(cci_pmu);
}

static inline u32 cci_pmu_read_register(int idx, unsigned int offset)
{
	return readl_relaxed(info->baseaddr + CCI400_PMU_CNTR_BASE(idx) + offset);
}

static inline void cci_pmu_write_register(u32 value, int idx, unsigned int offset)
{
	return writel_relaxed(value, info->baseaddr + CCI400_PMU_CNTR_BASE(idx) + offset);
}

static inline void cci_pmu_disable_counter(int idx)
{
	cci_pmu_write_register(0, idx, CCI400_PMU_CNTR_CTRL);
}

static inline void cci_pmu_enable_counter(int idx)
{
	cci_pmu_write_register(1, idx, CCI400_PMU_CNTR_CTRL);
}

static inline void cci_pmu_select_event(int idx, unsigned long event)
{
	event &= CCI400_PMU_EVENT_MASK;
	cci_pmu_write_register(event, idx, CCI400_PMU_EVT_SEL);
}

static u32 cci_pmu_get_max_counters(void)
{
	u32 n_cnts = (readl_relaxed(info->baseaddr + CCI400_PMCR) &
		      CCI400_PMCR_NCNT_MASK) >> CCI400_PMCR_NCNT_SHIFT;

	/* add 1 for cycle counter */
	return n_cnts + 1;
}

static struct pmu_hw_events *cci_pmu_get_hw_events(void)
{
	return &cci_hw_events;
}

static int cci_pmu_get_event_idx(struct pmu_hw_events *hw, struct perf_event *event)
{
	struct arm_pmu *cci_pmu = to_arm_pmu(event->pmu);
	struct hw_perf_event *hw_event = &event->hw;
	unsigned long cci_event = hw_event->config_base & CCI400_PMU_EVENT_MASK;
	int idx;

	if (cci_event == CCI400_PMU_CYCLES) {
		if (test_and_set_bit(CCI400_PMU_CYCLE_COUNTER_IDX, hw->used_mask))
			return -EAGAIN;

                return CCI400_PMU_CYCLE_COUNTER_IDX;
        }

	for (idx = CCI400_PMU_COUNTER0_IDX; idx <= CCI400_PMU_COUNTER_LAST(cci_pmu); ++idx) {
		if (!test_and_set_bit(idx, hw->used_mask))
			return idx;
	}

	/* No counters available */
	return -EAGAIN;
}

static int cci_pmu_map_event(struct perf_event *event)
{
	int mapping;
	u8 config = event->attr.config & CCI400_PMU_EVENT_MASK;

	if (event->attr.type < PERF_TYPE_MAX)
		return -ENOENT;

	/* 0xff is used to represent CCI Cycles */
	if (config == 0xff)
		mapping = config;
	else
		mapping = cci_pmu_validate_hw_event(config);

	return mapping;
}

static int cci_pmu_request_irq(struct arm_pmu *cci_pmu, irq_handler_t handler)
{
	int irq, err, i = 0;
	struct platform_device *pmu_device = cci_pmu->plat_device;

	if (unlikely(!pmu_device))
		return -ENODEV;

	/* CCI exports 6 interrupts - 1 nERRORIRQ + 5 nEVNTCNTOVERFLOW (PMU)
	   nERRORIRQ will be handled by secure firmware on TC2. So we
	   assume that all CCI interrupts listed in the linux device
	   tree are PMU interrupts.

	   The following code should then be able to handle different routing
	   of the CCI PMU interrupts.
	*/
	while ((irq = platform_get_irq(pmu_device, i)) > 0) {
		err = request_irq(irq, handler, 0, "arm-cci-pmu", cci_pmu);
		if (err) {
			dev_err(&pmu_device->dev, "unable to request IRQ%d for ARM CCI PMU counters\n",
				irq);
			return err;
		}
		i++;
	}

	return 0;
}

static irqreturn_t cci_pmu_handle_irq(int irq_num, void *dev)
{
	struct arm_pmu *cci_pmu = (struct arm_pmu *)dev;
	struct pmu_hw_events *events = cci_pmu->get_hw_events();
	struct perf_sample_data data;
	struct pt_regs *regs;
	int idx;

	regs = get_irq_regs();

	/* Iterate over counters and update the corresponding perf events.
	   This should work regardless of whether we have per-counter overflow
	   interrupt or a combined overflow interrupt. */
	for (idx = CCI400_PMU_CYCLE_COUNTER_IDX; idx <= CCI400_PMU_COUNTER_LAST(cci_pmu); idx++) {
		struct perf_event *event = events->events[idx];
		struct hw_perf_event *hw_counter;

		if (!event)
			continue;

		hw_counter = &event->hw;

		/* Did this counter overflow? */
		if (!(cci_pmu_read_register(idx, CCI400_PMU_OVERFLOW) & CCI400_PMU_OVERFLOW_FLAG))
			continue;
		cci_pmu_write_register(CCI400_PMU_OVERFLOW_FLAG, idx, CCI400_PMU_OVERFLOW);

		armpmu_event_update(event);
		perf_sample_data_init(&data, 0, hw_counter->last_period);
		if (!armpmu_event_set_period(event))
			continue;

		if (perf_event_overflow(event, &data, regs))
			cci_pmu->disable(event);
	}

	irq_work_run();
	return IRQ_HANDLED;
}

static void cci_pmu_free_irq(struct arm_pmu *cci_pmu)
{
	int irq, i = 0;
	struct platform_device *pmu_device = cci_pmu->plat_device;

	while ((irq = platform_get_irq(pmu_device, i)) > 0) {
		free_irq(irq, cci_pmu);
		i++;
	}
}

static void cci_pmu_enable_event(struct perf_event *event)
{
	unsigned long flags;
	struct arm_pmu *cci_pmu = to_arm_pmu(event->pmu);
	struct pmu_hw_events *events = cci_pmu->get_hw_events();
	struct hw_perf_event *hw_counter = &event->hw;
	int idx = hw_counter->idx;

	if (unlikely(!cci_pmu_counter_is_valid(cci_pmu, idx))) {
		dev_err(&cci_pmu->plat_device->dev, "Invalid CCI PMU counter %d\n", idx);
		return;
	}

	raw_spin_lock_irqsave(&events->pmu_lock, flags);

	/* Configure the event to count, unless you are counting cycles */
	if (idx != CCI400_PMU_CYCLE_COUNTER_IDX)
		cci_pmu_select_event(idx, hw_counter->config_base);

	cci_pmu_enable_counter(idx);

	raw_spin_unlock_irqrestore(&events->pmu_lock, flags);
}

static void cci_pmu_disable_event(struct perf_event *event)
{
	unsigned long flags;
	struct arm_pmu *cci_pmu = to_arm_pmu(event->pmu);
	struct pmu_hw_events *events = cci_pmu->get_hw_events();
	struct hw_perf_event *hw_counter = &event->hw;
	int idx = hw_counter->idx;

	if (unlikely(!cci_pmu_counter_is_valid(cci_pmu, idx))) {
		dev_err(&cci_pmu->plat_device->dev, "Invalid CCI PMU counter %d\n", idx);
		return;
	}

	raw_spin_lock_irqsave(&events->pmu_lock, flags);

	cci_pmu_disable_counter(idx);

	raw_spin_unlock_irqrestore(&events->pmu_lock, flags);
}

static void cci_pmu_start(struct arm_pmu *cci_pmu)
{
	u32 val;
	unsigned long flags;
	struct cci_drvdata *info = platform_get_drvdata(cci_pmu->plat_device);
	struct pmu_hw_events *events = cci_pmu->get_hw_events();

	raw_spin_lock_irqsave(&events->pmu_lock, flags);

	/* Enable all the PMU counters. */
	val = readl(info->baseaddr + CCI400_PMCR) | CCI400_PMCR_CEN;
	writel(val, info->baseaddr + CCI400_PMCR);

	raw_spin_unlock_irqrestore(&events->pmu_lock, flags);
}

static void cci_pmu_stop(struct arm_pmu *cci_pmu)
{
	u32 val;
	unsigned long flags;
	struct cci_drvdata *info = platform_get_drvdata(cci_pmu->plat_device);
	struct pmu_hw_events *events = cci_pmu->get_hw_events();

	raw_spin_lock_irqsave(&events->pmu_lock, flags);

	/* Disable all the PMU counters. */
	val = readl(info->baseaddr + CCI400_PMCR) & ~CCI400_PMCR_CEN;
	writel(val, info->baseaddr + CCI400_PMCR);

	raw_spin_unlock_irqrestore(&events->pmu_lock, flags);
}

static u32 cci_pmu_read_counter(struct perf_event *event)
{
	struct arm_pmu *cci_pmu = to_arm_pmu(event->pmu);
	struct hw_perf_event *hw_counter = &event->hw;
	int idx = hw_counter->idx;
	u32 value;

	if (unlikely(!cci_pmu_counter_is_valid(cci_pmu, idx))) {
		dev_err(&cci_pmu->plat_device->dev, "Invalid CCI PMU counter %d\n", idx);
		return 0;
	}
	value = cci_pmu_read_register(idx, CCI400_PMU_CNTR);

	return value;
}

static void cci_pmu_write_counter(struct perf_event *event, u32 value)
{
	struct arm_pmu *cci_pmu = to_arm_pmu(event->pmu);
	struct hw_perf_event *hw_counter = &event->hw;
	int idx = hw_counter->idx;

	if (unlikely(!cci_pmu_counter_is_valid(cci_pmu, idx)))
		dev_err(&cci_pmu->plat_device->dev, "Invalid CCI PMU counter %d\n", idx);
	else
		cci_pmu_write_register(value, idx, CCI400_PMU_CNTR);
}

static struct arm_pmu cci_pmu = {
	.name             = DRIVER_NAME,
	.max_period       = (1LLU << 32) - 1,
	.get_hw_events    = cci_pmu_get_hw_events,
	.get_event_idx    = cci_pmu_get_event_idx,
	.map_event        = cci_pmu_map_event,
	.request_irq      = cci_pmu_request_irq,
	.handle_irq       = cci_pmu_handle_irq,
	.free_irq         = cci_pmu_free_irq,
	.enable           = cci_pmu_enable_event,
	.disable          = cci_pmu_disable_event,
	.start            = cci_pmu_start,
	.stop             = cci_pmu_stop,
	.read_counter     = cci_pmu_read_counter,
	.write_counter    = cci_pmu_write_counter,
};

static int cci_pmu_init(struct platform_device *pdev)
{
	cci_pmu.plat_device = pdev;
	cci_pmu.num_events = cci_pmu_get_max_counters();
	raw_spin_lock_init(&cci_hw_events.pmu_lock);
	cpumask_setall(&cci_pmu.valid_cpus);

	return armpmu_register(&cci_pmu, -1);
}

static void cci_pmu_destroy(void)
{
	perf_pmu_unregister(&cci_pmu.pmu);
}

#else

static int cci_pmu_init(struct platform_device *pdev)
{
	return 0;
}

static void cci_pmu_destroy(void) { }

#endif /* CONFIG_HW_PERF_EVENTS */

void notrace disable_cci(int cluster)
{
	u32 cci_reg = cluster ? CCI400_KF_OFFSET : CCI400_EAG_OFFSET;
	writel_relaxed(0x0, info->baseaddr	+ cci_reg);

	while (readl_relaxed(info->baseaddr + 0xc) & 0x1)
			;
}
EXPORT_SYMBOL_GPL(disable_cci);

static int cci_driver_probe(struct platform_device *pdev)
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

	/*
	 * Multi-cluster systems may need this data when non-coherent, during
	 * cluster power-up/power-down. Make sure it reaches main memory:
	 */
	__cpuc_flush_dcache_area(info, sizeof *info);
	__cpuc_flush_dcache_area(&info, sizeof info);
	outer_clean_range(virt_to_phys(info), virt_to_phys(info + 1));
	outer_clean_range(virt_to_phys(&info), virt_to_phys(&info + 1));

	platform_set_drvdata(pdev, info);

	if (cci_pmu_init(pdev) < 0)
		pr_info("CCI PMU initialisation failed.\n");

	pr_info("CCI loaded at %p\n", info->baseaddr);
	return ret;

ioremap_err:
	release_region(res->start, resource_size(res));
mem_free:
	kfree(info);

	return ret;
}

static int cci_driver_remove(struct platform_device *pdev)
{
	struct cci_drvdata *info;
	struct resource *res = pdev->resource;

	cci_pmu_destroy();
	info = platform_get_drvdata(pdev);
	iounmap(info->baseaddr);
	release_region(res->start, resource_size(res));
	kfree(info);

	return 0;
}

static const struct of_device_id arm_cci_matches[] = {
	{.compatible = "arm,cci"},
	{},
};

static struct platform_driver cci_platform_driver = {
	.driver = {
		   .owner = THIS_MODULE,
		   .name = DRIVER_NAME,
		   .of_match_table = arm_cci_matches,
		   },
	.probe = cci_driver_probe,
	.remove = cci_driver_remove,
};

static int __init cci_init(void)
{
	return platform_driver_register(&cci_platform_driver);
}

static void __exit cci_exit(void)
{
	platform_driver_unregister(&cci_platform_driver);
}

core_initcall(cci_init);
module_exit(cci_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("CCI support");
