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

long vfio_platform_devtree_ioctl(struct vfio_platform_device *vdev,
				 unsigned long arg)
{
	return -EINVAL; /* not implemented yet */
}
