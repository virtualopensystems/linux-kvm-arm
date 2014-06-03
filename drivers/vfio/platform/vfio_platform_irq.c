/*
 * VFIO platform devices interrupt handling
 *
 * Copyright (C) 2013 - Virtual Open Systems
 * Author: Antonios Motakis <a.motakis@virtualopensystems.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 2, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <linux/device.h>
#include <linux/eventfd.h>
#include <linux/interrupt.h>
#include <linux/iommu.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/notifier.h>
#include <linux/pm_runtime.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/vfio.h>
#include <linux/platform_device.h>
#include <linux/irq.h>

#include "vfio_platform_private.h"

int vfio_platform_irq_init(struct vfio_platform_device *vdev)
{
	int cnt = 0, i;

	while (platform_get_irq(vdev->pdev, cnt) > 0)
		cnt++;

	vdev->irq = kzalloc(sizeof(struct vfio_platform_irq) * cnt, GFP_KERNEL);
	if (!vdev->irq)
		return -ENOMEM;

	for (i = 0; i < cnt; i++) {
		vdev->irq[i].flags = 0;
		vdev->irq[i].count = 1;
	}

	vdev->num_irqs = cnt;

	return 0;
}

void vfio_platform_irq_cleanup(struct vfio_platform_device *vdev)
{
	vdev->num_irqs = 0;
	kfree(vdev->irq);
}
