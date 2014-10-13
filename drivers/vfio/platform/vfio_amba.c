/*
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
#include <linux/io.h>
#include <linux/irq.h>
#include <linux/amba/bus.h>

#include "vfio_platform_private.h"

#define DRIVER_VERSION  "0.8"
#define DRIVER_AUTHOR   "Antonios Motakis <a.motakis@virtualopensystems.com>"
#define DRIVER_DESC     "VFIO for AMBA devices - User Level meta-driver"

/* probing devices from the AMBA bus */

static struct resource *get_amba_resource(struct vfio_platform_device *vdev,
						int i)
{
	struct amba_device *adev = (struct amba_device *) vdev->opaque;

	if (i == 0)
		return &adev->res;

	return NULL;
}

static int get_amba_irq(struct vfio_platform_device *vdev, int i)
{
	struct amba_device *adev = (struct amba_device *) vdev->opaque;

	if (i < AMBA_NR_IRQS)
		return adev->irq[i];

	return 0;
}

static int vfio_amba_probe(struct amba_device *adev, const struct amba_id *id)
{

	struct vfio_platform_device *vdev;
	int ret;

	vdev = kzalloc(sizeof(*vdev), GFP_KERNEL);
	if (!vdev)
		return -ENOMEM;

	vdev->opaque = (void *) adev;
	vdev->name = "vfio-amba-dev";
	vdev->flags = VFIO_DEVICE_FLAGS_AMBA;
	vdev->get_resource = get_amba_resource;
	vdev->get_irq = get_amba_irq;

	ret = vfio_platform_probe_common(vdev, &adev->dev);
	if (ret)
		kfree(vdev);

	return ret;
}

static int vfio_amba_remove(struct amba_device *adev)
{
	return vfio_platform_remove_common(&adev->dev);
}

static struct amba_id pl330_ids[] = {
	{ 0, 0 },
};

MODULE_DEVICE_TABLE(amba, pl330_ids);

static struct amba_driver vfio_amba_driver = {
	.probe = vfio_amba_probe,
	.remove = vfio_amba_remove,
	.id_table = pl330_ids,
	.drv = {
		.name = "vfio-amba",
		.owner = THIS_MODULE,
	},
};

module_amba_driver(vfio_amba_driver);

MODULE_VERSION(DRIVER_VERSION);
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR(DRIVER_AUTHOR);
MODULE_DESCRIPTION(DRIVER_DESC);
