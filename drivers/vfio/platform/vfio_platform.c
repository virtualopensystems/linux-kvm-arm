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
#include <linux/io.h>
#include <linux/platform_device.h>
#include <linux/irq.h>

#include "vfio_platform_private.h"

#define DRIVER_VERSION  "0.5"
#define DRIVER_AUTHOR   "Antonios Motakis <a.motakis@virtualopensystems.com>"
#define DRIVER_DESC     "VFIO for platform devices - User Level meta-driver"

static int vfio_platform_regions_init(struct vfio_platform_device *vdev)
{
	int cnt = 0, i;

	while (platform_get_resource(vdev->pdev, IORESOURCE_MEM, cnt))
		cnt++;

	vdev->num_regions = cnt;

	vdev->region = kzalloc(sizeof(struct vfio_platform_region) * cnt,
				GFP_KERNEL);
	if (!vdev->region)
		return -ENOMEM;

	for (i = 0; i < cnt;  i++) {
		struct vfio_platform_region region;
		struct resource *res =
			platform_get_resource(vdev->pdev, IORESOURCE_MEM, i);

		region.addr = res->start;
		region.size = resource_size(res);
		region.flags = VFIO_REGION_INFO_FLAG_READ
				| VFIO_REGION_INFO_FLAG_WRITE;

		/* Only regions addressed with PAGE granularity can be MMAPed
		 * securely. */
		if (!(region.addr & ~PAGE_MASK) && !(region.size & ~PAGE_MASK))
			region.flags |= VFIO_REGION_INFO_FLAG_MMAP;

		vdev->region[i] = region;
	}

	return 0;
}

static void vfio_platform_regions_cleanup(struct vfio_platform_device *vdev)
{
	kfree(vdev->region);
}

static void vfio_platform_release(void *device_data)
{
	struct vfio_platform_device *vdev = device_data;

	vfio_platform_regions_cleanup(vdev);
	vfio_platform_irq_cleanup(vdev);

	module_put(THIS_MODULE);
}

static int vfio_platform_open(void *device_data)
{
	struct vfio_platform_device *vdev = device_data;
	int ret;

	ret = vfio_platform_regions_init(vdev);
	if (ret)
		return ret;

	ret = vfio_platform_irq_init(vdev);
	if (ret)
		goto err_irq;

	if (!try_module_get(THIS_MODULE)) {
		ret = -ENODEV;
		goto err_mod;
	}

	return 0;

err_mod:
	vfio_platform_irq_cleanup(vdev);
err_irq:
	vfio_platform_regions_cleanup(vdev);
	return ret;
}

static long vfio_platform_ioctl(void *device_data,
			   unsigned int cmd, unsigned long arg)
{
	struct vfio_platform_device *vdev = device_data;
	unsigned long minsz;

	if (cmd == VFIO_DEVICE_GET_INFO) {
		struct vfio_device_info info;

		minsz = offsetofend(struct vfio_device_info, num_irqs);

		if (copy_from_user(&info, (void __user *)arg, minsz))
			return -EFAULT;

		if (info.argsz < minsz)
			return -EINVAL;

		info.flags = VFIO_DEVICE_FLAGS_PLATFORM;
		info.num_regions = vdev->num_regions;
		info.num_irqs = vdev->num_irqs;

		return copy_to_user((void __user *)arg, &info, minsz);

	} else if (cmd == VFIO_DEVICE_GET_REGION_INFO) {
		struct vfio_region_info info;

		minsz = offsetofend(struct vfio_region_info, offset);

		if (copy_from_user(&info, (void __user *)arg, minsz))
			return -EFAULT;

		if (info.argsz < minsz)
			return -EINVAL;

		if (info.index >= vdev->num_regions)
			return -EINVAL;

		/* map offset to the physical address  */
		info.offset = VFIO_PLATFORM_INDEX_TO_OFFSET(info.index);
		info.size = vdev->region[info.index].size;
		info.flags = vdev->region[info.index].flags;

		return copy_to_user((void __user *)arg, &info, minsz);

	} else if (cmd == VFIO_DEVICE_GET_IRQ_INFO) {
		struct vfio_irq_info info;

		minsz = offsetofend(struct vfio_irq_info, count);

		if (copy_from_user(&info, (void __user *)arg, minsz))
			return -EFAULT;

		if (info.argsz < minsz)
			return -EINVAL;

		if (info.index >= vdev->num_irqs)
			return -EINVAL;

		info.flags = vdev->irq[info.index].flags;
		info.count = vdev->irq[info.index].count;

		return copy_to_user((void __user *)arg, &info, minsz);

	} else if (cmd == VFIO_DEVICE_SET_IRQS)
		return -EINVAL;

	else if (cmd == VFIO_DEVICE_RESET)
		return -EINVAL;

	return -ENOTTY;
}

static ssize_t vfio_platform_read(void *device_data, char __user *buf,
			     size_t count, loff_t *ppos)
{
	struct vfio_platform_device *vdev = device_data;
	unsigned int index = VFIO_PLATFORM_OFFSET_TO_INDEX(*ppos);
	loff_t off = *ppos & VFIO_PLATFORM_OFFSET_MASK;
	unsigned int done = 0;
	void __iomem *io;

	if (index >= vdev->num_regions)
		return -EINVAL;

	io = ioremap_nocache(vdev->region[index].addr,
			     vdev->region[index].size);

	while (count) {
		size_t filled;

		if (count >= 4 && !(off % 4)) {
			u32 val;

			val = ioread32(io + off);
			if (copy_to_user(buf, &val, 4))
				goto err;

			filled = 4;
		} else if (count >= 2 && !(off % 2)) {
			u16 val;

			val = ioread16(io + off);
			if (copy_to_user(buf, &val, 2))
				goto err;

			filled = 2;
		} else {
			u8 val;

			val = ioread8(io + off);
			if (copy_to_user(buf, &val, 1))
				goto err;

			filled = 1;
		}


		count -= filled;
		done += filled;
		off += filled;
		buf += filled;
	}

	iounmap(io);
	return done;
err:
	iounmap(io);
	return -EFAULT;
}

static ssize_t vfio_platform_write(void *device_data, const char __user *buf,
			      size_t count, loff_t *ppos)
{
	struct vfio_platform_device *vdev = device_data;
	unsigned int index = VFIO_PLATFORM_OFFSET_TO_INDEX(*ppos);
	loff_t off = *ppos & VFIO_PLATFORM_OFFSET_MASK;
	unsigned int done = 0;
	void __iomem *io;

	if (index >= vdev->num_regions)
		return -EINVAL;

	io = ioremap_nocache(vdev->region[index].addr,
			     vdev->region[index].size);

	while (count) {
		size_t filled;

		if (count >= 4 && !(off % 4)) {
			u32 val;

			if (copy_from_user(&val, buf, 4))
				goto err;
			iowrite32(val, io + off);

			filled = 4;
		} else if (count >= 2 && !(off % 2)) {
			u16 val;

			if (copy_from_user(&val, buf, 2))
				goto err;
			iowrite16(val, io + off);

			filled = 2;
		} else {
			u8 val;

			if (copy_from_user(&val, buf, 1))
				goto err;
			iowrite8(val, io + off);

			filled = 1;
		}

		count -= filled;
		done += filled;
		off += filled;
		buf += filled;
	}

	iounmap(io);
	return done;
err:
	iounmap(io);
	return -EFAULT;
}

static int vfio_platform_mmap(void *device_data, struct vm_area_struct *vma)
{
	struct vfio_platform_device *vdev = device_data;
	unsigned int index;
	u64 req_len, pgoff, req_start;
	struct vfio_platform_region region;

	index = vma->vm_pgoff >> (VFIO_PLATFORM_OFFSET_SHIFT - PAGE_SHIFT);

	if (vma->vm_end < vma->vm_start)
		return -EINVAL;
	if ((vma->vm_flags & VM_SHARED) == 0)
		return -EINVAL;
	if (index >= vdev->num_regions)
		return -EINVAL;
	if (vma->vm_start & ~PAGE_MASK)
		return -EINVAL;
	if (vma->vm_end & ~PAGE_MASK)
		return -EINVAL;

	region = vdev->region[index];

	req_len = vma->vm_end - vma->vm_start;
	pgoff = vma->vm_pgoff &
		((1U << (VFIO_PLATFORM_OFFSET_SHIFT - PAGE_SHIFT)) - 1);
	req_start = pgoff << PAGE_SHIFT;

	if (region.size < PAGE_SIZE || req_start + req_len > region.size)
		return -EINVAL;

	vma->vm_private_data = vdev;
	vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
	vma->vm_pgoff = (region.addr >> PAGE_SHIFT) + pgoff;

	return remap_pfn_range(vma, vma->vm_start, vma->vm_pgoff,
			       req_len, vma->vm_page_prot);
}

static const struct vfio_device_ops vfio_platform_ops = {
	.name		= "vfio-platform",
	.open		= vfio_platform_open,
	.release	= vfio_platform_release,
	.ioctl		= vfio_platform_ioctl,
	.read		= vfio_platform_read,
	.write		= vfio_platform_write,
	.mmap		= vfio_platform_mmap,
};

static int vfio_platform_probe(struct platform_device *pdev)
{
	struct vfio_platform_device *vdev;
	struct iommu_group *group;
	int ret;

	group = iommu_group_get(&pdev->dev);
	if (!group) {
		pr_err("VFIO: No IOMMU group for device %s\n", pdev->name);
		return -EINVAL;
	}

	vdev = kzalloc(sizeof(*vdev), GFP_KERNEL);
	if (!vdev) {
		iommu_group_put(group);
		return -ENOMEM;
	}

	vdev->pdev = pdev;

	ret = vfio_add_group_dev(&pdev->dev, &vfio_platform_ops, vdev);
	if (ret) {
		iommu_group_put(group);
		kfree(vdev);
	}

	return ret;
}

static int vfio_platform_remove(struct platform_device *pdev)
{
	struct vfio_platform_device *vdev;

	vdev = vfio_del_group_dev(&pdev->dev);
	if (!vdev)
		return -EINVAL;

	iommu_group_put(pdev->dev.iommu_group);
	kfree(vdev);

	return 0;
}

static struct platform_driver vfio_platform_driver = {
	.probe		= vfio_platform_probe,
	.remove		= vfio_platform_remove,
	.driver	= {
		.name	= "vfio-platform",
		.owner	= THIS_MODULE,
	},
};

module_platform_driver(vfio_platform_driver);

MODULE_VERSION(DRIVER_VERSION);
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR(DRIVER_AUTHOR);
MODULE_DESCRIPTION(DRIVER_DESC);
