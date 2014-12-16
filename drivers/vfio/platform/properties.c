/*
 * Copyright (C) 2015 - Virtual Open Systems
 * Authors: Antonios Motakis <a.motakis@virtualopensystems.com>
 * 	    Baptiste Reynal <b.reynal@virtualopensystems.com>
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

#include <linux/slab.h>
#include <linux/vfio.h>
#include <linux/property.h>
#include "vfio_platform_private.h"

static int dev_property_get_strings(struct device *dev, uint32_t *flags,
				    char *name, unsigned *lenp,
				    void __user *datap, unsigned long datasz)
{
	return -EINVAL;
}

static int dev_property_get_uint(struct device *dev, uint32_t *flags,
				 char *name, uint32_t type, unsigned *lenp,
				 void __user *datap, unsigned long datasz)
{
	return -EINVAL;
}

int vfio_platform_dev_properties(struct device *dev, uint32_t *flags,
				 uint32_t type, unsigned *lenp,
				 void __user *datap, unsigned long datasz)
{
	char *name;
	long namesz;
	int ret;

	namesz = strnlen_user(datap, datasz);
	if (!namesz)
		return -EFAULT;
	if (namesz > datasz)
		return -EINVAL;

	name = kzalloc(namesz, GFP_KERNEL);
	if (!name)
		return -ENOMEM;
	if (strncpy_from_user(name, datap, namesz) <= 0) {
		kfree(name);
		return -EFAULT;
	}

	switch (type) {
	case VFIO_DEV_PROPERTY_TYPE_STRINGS:
		ret = dev_property_get_strings(dev, flags, name, lenp,
				datap, datasz);
		break;

	case VFIO_DEV_PROPERTY_TYPE_U64:
	case VFIO_DEV_PROPERTY_TYPE_U32:
	case VFIO_DEV_PROPERTY_TYPE_U16:
	case VFIO_DEV_PROPERTY_TYPE_U8:
		ret = dev_property_get_uint(dev, flags, name, type, lenp,
					    datap, datasz);
		break;

	default:
		ret = -EINVAL;
	}

	kfree(name);
	return ret;
}
