#include <linux/slab.h>
#include <linux/vfio.h>
#include <linux/property.h>
#include "vfio_platform_private.h"

static int dev_property_get_strings(struct device *dev,
				    char *name, unsigned *lenp,
				    void __user *datap, unsigned long datasz)
{
	const char **val;
	int n, i, ret;

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

	ret = 0;

	for (i = 0; i < n; i++) {
		size_t len = strlen(val[i]) + 1;

		if (datasz < len) {
			ret = -EOVERFLOW;
			while (i < n)
				*lenp += strlen(val[i++]) + 1;
			goto out;
		}

		if (copy_to_user(datap, val[i], len)) {
			ret = -EFAULT;
			goto out;
		}

		*lenp += len;
		datap += len;
		datasz -= len;
	}

out:
	kfree(val);
	return ret;
}

static int dev_property_get_uint(struct device *dev, char *name,
				 uint32_t type, unsigned *lenp,
				 void __user *datap, unsigned long datasz)
{
	return -EINVAL;
}

int vfio_platform_dev_properties(struct device *dev,
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
		ret = dev_property_get_strings(dev, name, lenp, datap, datasz);
		break;

	case VFIO_DEV_PROPERTY_TYPE_U64:
	case VFIO_DEV_PROPERTY_TYPE_U32:
	case VFIO_DEV_PROPERTY_TYPE_U16:
	case VFIO_DEV_PROPERTY_TYPE_U8:
		ret = dev_property_get_uint(dev, name, type, lenp,
					    datap, datasz);
		break;

	default:
		ret = -EINVAL;
	}

	kfree(name);
	return ret;
}
