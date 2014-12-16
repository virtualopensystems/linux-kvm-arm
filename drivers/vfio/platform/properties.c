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
	const char **val;
	int n, i, ret;

	if (lenp == NULL)
		return -EFAULT;

	*lenp = 0;

	n = device_property_read_string_array(dev, name, NULL, 0);
	if (n < 0)
		return n;

	val = kcalloc(n, sizeof(char*), GFP_KERNEL);
	if (!val)
		return -ENOMEM;

	ret = device_property_read_string_array(dev, name, val, n);
	if (ret < 0)
		goto out;

	for (i = 0; i < n; i++) {
		*lenp += strlen(val[i]) + 1;
	}

	if (datasz < *lenp) {
		ret = -E2BIG;
		goto out;
	}

	for (i = 0; i < n; i++) {
		size_t len = strlen(val[i]) + 1;

		if (copy_to_user(datap, val[i], strlen(val[i]) + 1)) {
			ret = -EFAULT;
			goto out;
		}

		datap += len;
	}

out:
	kfree(val);
	return ret;
}

static int dev_property_get_uint(struct device *dev, uint32_t *flags,
				 char *name, uint32_t type, unsigned *lenp,
				 void __user *datap, unsigned long datasz)
{
	int ret, n;
	u8 *out;
	size_t sz;
	int (*func)(const struct device *, const char *, void *, size_t)
		= NULL;

	switch (type) {
	case VFIO_DEV_PROPERTY_TYPE_U64:
		sz = sizeof(u64);
		func = (int (*)(const struct device *,
				const char *, void *, size_t))
			device_property_read_u64_array;
		break;
	case VFIO_DEV_PROPERTY_TYPE_U32:
		sz = sizeof(u32);
		func = (int (*)(const struct device *,
				const char *, void *, size_t))
			device_property_read_u32_array;
		break;
	case VFIO_DEV_PROPERTY_TYPE_U16:
		sz = sizeof(u16);
		func = (int (*)(const struct device *,
				const char *, void *, size_t))
			device_property_read_u16_array;
		break;
	case VFIO_DEV_PROPERTY_TYPE_U8:
		sz = sizeof(u8);
		func = (int (*)(const struct device *,
				const char *, void *, size_t))
			device_property_read_u8_array;
		break;

	default:
		return -EINVAL;
	}

	/* get size of array */
	n = func(dev, name, NULL, 0);
	if (n < 0)
		return n;

	if (lenp)
		*lenp = n * sz;

	if (n * sz > datasz)
		return -EOVERFLOW;

	out = kcalloc(n, sz, GFP_KERNEL);
	if (!out)
		return -ENOMEM;

	ret = func(dev, name, out, n);
	if (ret)
		goto out;

	if (copy_to_user(datap, out, n * sz))
		ret = -EFAULT;

out:
	kfree(out);
	return ret;
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
