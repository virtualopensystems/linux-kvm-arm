#include <linux/slab.h>
#include <linux/vfio.h>
#include <linux/of.h>
#include <linux/platform_device.h>
#include "vfio_platform_private.h"

void vfio_platform_devtree_get(struct vfio_platform_device *vdev)
{
	vdev->of_node = of_node_get(vdev->pdev->dev.of_node);
}

void vfio_platform_devtree_put(struct vfio_platform_device *vdev)
{
	of_node_put(vdev->of_node);
	vdev->of_node = NULL;
}

bool vfio_platform_has_devtree(struct vfio_platform_device *vdev)
{
	return !!vdev->of_node;
}

static int devtree_get_prop_names(struct device_node *np, void __user *datap,
				  unsigned long datasz, int *lenp)
{
	struct property *prop;
	int len = 0, sz;
	int ret = 0;

	for_each_property_of_node(np, prop) {
		sz = strlen(prop->name) + 1;

		if (datasz < sz) {
			ret = -EAGAIN;
			break;
		}

		if (copy_to_user(datap, prop->name, sz))
			return -EFAULT;

		datap += sz;
		datasz -= sz;
		len += sz;
	}

	/* if overflow occurs, calculate remaining length */
	while (prop) {
		len += strlen(prop->name) + 1;
		prop = prop->next;
	}

	/* we expose the full_name in addition to the usual properties */
	len += sz = strlen("full_name") + 1;
	if (datasz < sz) {
		ret = -EAGAIN;
	} else if (copy_to_user(datap, "full_name", sz))
		return -EFAULT;

	*lenp = len;

	return ret;
}

static int devtree_get_strings(struct device_node *np, char *name,
			       void __user *datap, unsigned long datasz)
{
	struct property *prop;
	int len;

	prop = of_find_property(np, name, &len);

	if (!prop)
		return -EINVAL;

	if (len > datasz)
		return -EAGAIN;

	if (copy_to_user(datap, prop->value, len))
		return -EFAULT;
	else
		return 0;
}

static int devtree_get_full_name(struct device_node *np, void __user *datap,
				 unsigned long datasz, int *lenp)
{
	int len = strlen(np->full_name) + 1;

	if (lenp)
		*lenp = len;

	if (len > datasz)
		return -EAGAIN;

	if (copy_to_user(datap, np->full_name, len))
		return -EFAULT;

	return 0;
}

static int devtree_get_u32_arr(const struct device_node *np, const char *name,
			       void __user *datap, unsigned long datasz)
{
	int ret;
	int n;
	u32 *out;

	n = of_property_count_elems_of_size(np, name, sizeof(u32));
	if (n < 0)
		return n;

	if (n * sizeof(u32) > datasz)
		return -EAGAIN;

	out = kcalloc(n, sizeof(u32), GFP_KERNEL);
	if (!out)
		return -EFAULT;

	ret = of_property_read_u32_array(np, name, out, n);
	if (ret)
		goto out;

	if (copy_to_user(datap, out, n * sizeof(u32)))
		ret = -EFAULT;

out:
	kfree(out);
	return ret;
}

static int devtree_get_u16_arr(const struct device_node *np, const char *name,
			       void __user *datap, unsigned long datasz)
{
	int ret;
	int n;
	u16 *out;

	n = of_property_count_elems_of_size(np, name, sizeof(u16));
	if (n < 0)
		return n;

	if (n * sizeof(u16) > datasz)
		return -EAGAIN;

	out = kcalloc(n, sizeof(u16), GFP_KERNEL);
	if (!out)
		return -EFAULT;

	ret = of_property_read_u16_array(np, name, out, n);
	if (ret)
		goto out;

	if (copy_to_user(datap, out, n * sizeof(u16)))
		ret = -EFAULT;

out:
	kfree(out);
	return ret;
}

static int devtree_get_u8_arr(const struct device_node *np, const char *name,
			       void __user *datap, unsigned long datasz)
{
	int ret;
	int n;
	u8 *out;

	n = of_property_count_elems_of_size(np, name, sizeof(u8));
	if (n < 0)
		return n;

	if (n * sizeof(u8) > datasz)
		return -EAGAIN;

	out = kcalloc(n, sizeof(u8), GFP_KERNEL);
	if (!out)
		return -EFAULT;

	ret = of_property_read_u8_array(np, name, out, n);
	if (ret)
		goto out;

	if (copy_to_user(datap, out, n * sizeof(u8)))
		ret = -EFAULT;

out:
	kfree(out);
	return ret;
}

long vfio_platform_devtree_ioctl(struct vfio_platform_device *vdev,
				 unsigned long arg)
{
	struct vfio_devtree_info info;
	unsigned long minsz = offsetofend(struct vfio_devtree_info, length);
	void __user *datap = (void __user *) arg + minsz;
	unsigned long int datasz;
	char *name;
	int ret = -EINVAL;

	if (!vfio_platform_has_devtree(vdev))
		return -EINVAL;

	if (copy_from_user(&info, (void __user *)arg, minsz))
		return -EFAULT;

	if (info.argsz < minsz)
		return -EINVAL;

	datasz = info.argsz - minsz;

	if (info.type == VFIO_DEVTREE_PROP_NAMES) {
		ret = devtree_get_prop_names(vdev->of_node, datap, datasz,
								&info.length);
		goto out;
	}

	name = kzalloc(datasz, GFP_KERNEL);
	if (!name)
		return -ENOMEM;
	if (copy_from_user(name, datap, datasz))
		return -EFAULT;

	if (!of_find_property(vdev->of_node, name, &info.length)) {
		/* special case full_name as a property that is not on the fdt,
		 * but we wish to return to the user as it includes the full
		 * path of the device */
		if (!strcmp(name, "full_name") &&
				(info.type == VFIO_DEVTREE_ARR_TYPE_STRING))
			ret = devtree_get_full_name(vdev->of_node, datap,
						    datasz, &info.length);

	} else if (info.type == VFIO_DEVTREE_ARR_TYPE_STRING)
		ret = devtree_get_strings(vdev->of_node, name, datap, datasz);

	else if (info.type == VFIO_DEVTREE_ARR_TYPE_U32)
		ret = devtree_get_u32_arr(vdev->of_node, name, datap, datasz);

	else if (info.type == VFIO_DEVTREE_ARR_TYPE_U16)
		ret = devtree_get_u16_arr(vdev->of_node, name, datap, datasz);

	else if (info.type == VFIO_DEVTREE_ARR_TYPE_U8)
		ret = devtree_get_u8_arr(vdev->of_node, name, datap, datasz);

	kfree(name);

out:
	if (copy_to_user((void __user *)arg, &info, minsz))
		ret = -EFAULT;

	return ret;
}
