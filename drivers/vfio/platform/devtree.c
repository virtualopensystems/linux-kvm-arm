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

long vfio_platform_devtree_ioctl(struct vfio_platform_device *vdev,
				 unsigned long arg)
{
	struct vfio_devtree_info info;
	unsigned long minsz = offsetofend(struct vfio_devtree_info, length);
	void __user *datap = (void __user *) arg + minsz;
	unsigned long int datasz;
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
	}

	if (copy_to_user((void __user *)arg, &info, minsz))
		ret = -EFAULT;

	return ret;
}
