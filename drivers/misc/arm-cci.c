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

#define CCI400_EAG_OFFSET       0x4000
#define CCI400_KF_OFFSET        0x5000

#define DRIVER_NAME	"CCI"
struct cci_drvdata {
	void __iomem *baseaddr;
	spinlock_t lock;
};

static struct cci_drvdata *info;

void notrace disable_cci(int cluster)
{
	u32 cci_reg = cluster ? CCI400_KF_OFFSET : CCI400_EAG_OFFSET;
	writel_relaxed(0x0, info->baseaddr	+ cci_reg);

	while (readl_relaxed(info->baseaddr + 0xc) & 0x1)
			;
}
EXPORT_SYMBOL_GPL(disable_cci);

static int __devinit cci_driver_probe(struct platform_device *pdev)
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

	platform_set_drvdata(pdev, info);

	pr_info("CCI loaded at %p\n", info->baseaddr);
	return ret;

ioremap_err:
	release_region(res->start, resource_size(res));
mem_free:
	kfree(info);

	return ret;
}

static int __devexit cci_driver_remove(struct platform_device *pdev)
{
	struct cci_drvdata *info;
	struct resource *res = pdev->resource;

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

arch_initcall(cci_init);
module_exit(cci_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("CCI support");
