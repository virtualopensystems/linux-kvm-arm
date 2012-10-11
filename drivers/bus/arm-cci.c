/*
 * ARM Cache Coherency Interconnect (CCI400) support
 *
 * Copyright (C) 2012-2013 ARM Ltd.
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


#define CCI_STATUS_OFFSET	0xc
#define STATUS_CHANGE_PENDING	(1 << 0)

#define CCI_SLAVE_OFFSET(n)	(0x1000 + 0x1000 * (n))
#define CCI400_EAG_OFFSET       CCI_SLAVE_OFFSET(3)
#define CCI400_KF_OFFSET        CCI_SLAVE_OFFSET(4)

#define DRIVER_NAME	"CCI"
struct cci_drvdata {
	void __iomem *baseaddr;
};

static struct cci_drvdata *info;

void notrace disable_cci(int cluster)
{
	u32 slave_reg = cluster ? CCI400_KF_OFFSET : CCI400_EAG_OFFSET;
	writel_relaxed(0x0, info->baseaddr + slave_reg);

	while (readl_relaxed(info->baseaddr + CCI_STATUS_OFFSET)
						& STATUS_CHANGE_PENDING)
			barrier();
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
		ret = -EADDRNOTAVAIL;
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

	pr_info("CCI loaded at %p\n", info->baseaddr);
	return ret;

ioremap_err:
	release_region(res->start, resource_size(res));
mem_free:
	kfree(info);

	return ret;
}

static const struct of_device_id arm_cci_matches[] = {
	{.compatible = "arm,cci"},
	{},
};

static struct platform_driver cci_platform_driver = {
	.driver = {
		   .name = DRIVER_NAME,
		   .of_match_table = arm_cci_matches,
		  },
	.probe = cci_driver_probe,
};

static int __init cci_init(void)
{
	return platform_driver_register(&cci_platform_driver);
}

core_initcall(cci_init);
