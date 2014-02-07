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

#ifndef VFIO_PLATFORM_PRIVATE_H
#define VFIO_PLATFORM_PRIVATE_H

#define VFIO_PLATFORM_OFFSET_SHIFT   40
#define VFIO_PLATFORM_OFFSET_MASK (((u64)(1) << VFIO_PLATFORM_OFFSET_SHIFT) - 1)

#define VFIO_PLATFORM_OFFSET_TO_INDEX(off)	\
	(off >> VFIO_PLATFORM_OFFSET_SHIFT)

#define VFIO_PLATFORM_INDEX_TO_OFFSET(index)	\
	((u64)(index) << VFIO_PLATFORM_OFFSET_SHIFT)

struct vfio_platform_irq {
	struct eventfd_ctx	*trigger;
	u32			flags;
	u32			count;
	int			hwirq;
	char			*name;
};

struct vfio_platform_region {
	u64			addr;
	resource_size_t		size;
	u32			flags;
};

struct vfio_platform_device {
	struct platform_device		*pdev;
	struct vfio_platform_region	*region;
	u32				num_regions;
	struct vfio_platform_irq	*irq;
	u32				num_irqs;
};

extern int vfio_platform_irq_init(struct vfio_platform_device *vdev);

extern void vfio_platform_irq_cleanup(struct vfio_platform_device *vdev);

extern int vfio_platform_set_irqs_ioctl(struct vfio_platform_device *vdev,
			uint32_t flags, unsigned index, unsigned start,
			unsigned count, void *data);

#endif /* VFIO_PLATFORM_PRIVATE_H */
