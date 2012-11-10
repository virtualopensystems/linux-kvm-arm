/*
 * Copyright (C) 2012 ARM Ltd.
 * Author: Marc Zyngier <marc.zyngier@arm.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

#include <linux/kvm.h>
#include <linux/kvm_host.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <asm/kvm_emulate.h>

#define VGIC_ADDR_UNDEF		(-1)
#define IS_VGIC_ADDR_UNDEF(_x)  ((_x) == (typeof(_x))VGIC_ADDR_UNDEF)

#define VGIC_DIST_SIZE		0x1000
#define VGIC_CPU_SIZE		0x2000


#define ACCESS_READ_VALUE	(1 << 0)
#define ACCESS_READ_RAZ		(0 << 0)
#define ACCESS_READ_MASK(x)	((x) & (1 << 0))
#define ACCESS_WRITE_IGNORED	(0 << 1)
#define ACCESS_WRITE_SETBIT	(1 << 1)
#define ACCESS_WRITE_CLEARBIT	(2 << 1)
#define ACCESS_WRITE_VALUE	(3 << 1)
#define ACCESS_WRITE_MASK(x)	((x) & (3 << 1))

/**
 * vgic_reg_access - access vgic register
 * @mmio:   pointer to the data describing the mmio access
 * @reg:    pointer to the virtual backing of the vgic distributor struct
 * @offset: least significant 2 bits used for word offset
 * @mode:   ACCESS_ mode (see defines above)
 *
 * Helper to make vgic register access easier using one of the access
 * modes defined for vgic register access
 * (read,raz,write-ignored,setbit,clearbit,write)
 */
static void vgic_reg_access(struct kvm_exit_mmio *mmio, u32 *reg,
			    u32 offset, int mode)
{
	int word_offset = offset & 3;
	int shift = word_offset * 8;
	u32 mask;
	u32 regval;

	/*
	 * Any alignment fault should have been delivered to the guest
	 * directly (ARM ARM B3.12.7 "Prioritization of aborts").
	 */

	mask = (~0U) >> (word_offset * 8);
	if (reg)
		regval = *reg;
	else {
		BUG_ON(mode != (ACCESS_READ_RAZ | ACCESS_WRITE_IGNORED));
		regval = 0;
	}

	if (mmio->is_write) {
		u32 data = (*((u32 *)mmio->data) & mask) << shift;
		switch (ACCESS_WRITE_MASK(mode)) {
		case ACCESS_WRITE_IGNORED:
			return;

		case ACCESS_WRITE_SETBIT:
			regval |= data;
			break;

		case ACCESS_WRITE_CLEARBIT:
			regval &= ~data;
			break;

		case ACCESS_WRITE_VALUE:
			regval = (regval & ~(mask << shift)) | data;
			break;
		}
		*reg = regval;
	} else {
		switch (ACCESS_READ_MASK(mode)) {
		case ACCESS_READ_RAZ:
			regval = 0;
			/* fall through */

		case ACCESS_READ_VALUE:
			*((u32 *)mmio->data) = (regval >> shift) & mask;
		}
	}
}

/* All this should be handled by kvm_bus_io_*()... FIXME!!! */
struct mmio_range {
	unsigned long base;
	unsigned long len;
	bool (*handle_mmio)(struct kvm_vcpu *vcpu, struct kvm_exit_mmio *mmio,
			    u32 offset);
};

static const struct mmio_range vgic_ranges[] = {
	{}
};

static const
struct mmio_range *find_matching_range(const struct mmio_range *ranges,
				       struct kvm_exit_mmio *mmio,
				       unsigned long base)
{
	const struct mmio_range *r = ranges;
	unsigned long addr = mmio->phys_addr - base;

	while (r->len) {
		if (addr >= r->base &&
		    (addr + mmio->len) <= (r->base + r->len))
			return r;
		r++;
	}

	return NULL;
}

/**
 * vgic_handle_mmio - handle an in-kernel MMIO access
 * @vcpu:	pointer to the vcpu performing the access
 * @mmio:	pointer to the data describing the access
 *
 * returns true if the MMIO access has been performed in kernel space,
 * and false if it needs to be emulated in user space.
 */
bool vgic_handle_mmio(struct kvm_vcpu *vcpu, struct kvm_run *run, struct kvm_exit_mmio *mmio)
{
	return KVM_EXIT_MMIO;
}

static bool vgic_ioaddr_overlap(struct kvm *kvm)
{
	phys_addr_t dist = kvm->arch.vgic.vgic_dist_base;
	phys_addr_t cpu = kvm->arch.vgic.vgic_cpu_base;

	if (IS_VGIC_ADDR_UNDEF(dist) || IS_VGIC_ADDR_UNDEF(cpu))
		return false;
	if ((dist <= cpu && dist + VGIC_DIST_SIZE > cpu) ||
	    (cpu <= dist && cpu + VGIC_CPU_SIZE > dist))
		return true;
	return false;
}

int kvm_vgic_set_addr(struct kvm *kvm, unsigned long type, u64 addr)
{
	int r = 0;
	struct vgic_dist *vgic = &kvm->arch.vgic;

	if (addr & ~KVM_PHYS_MASK)
		return -E2BIG;

	if (addr & ~PAGE_MASK)
		return -EINVAL;

	mutex_lock(&kvm->lock);
	switch (type) {
	case KVM_VGIC_V2_ADDR_TYPE_DIST:
		if (!IS_VGIC_ADDR_UNDEF(vgic->vgic_dist_base))
			return -EEXIST;
		if (addr + VGIC_DIST_SIZE < addr)
			return -EINVAL;
		kvm->arch.vgic.vgic_dist_base = addr;
		break;
	case KVM_VGIC_V2_ADDR_TYPE_CPU:
		if (!IS_VGIC_ADDR_UNDEF(vgic->vgic_cpu_base))
			return -EEXIST;
		if (addr + VGIC_CPU_SIZE < addr)
			return -EINVAL;
		kvm->arch.vgic.vgic_cpu_base = addr;
		break;
	default:
		r = -ENODEV;
	}

	if (vgic_ioaddr_overlap(kvm)) {
		kvm->arch.vgic.vgic_dist_base = VGIC_ADDR_UNDEF;
		kvm->arch.vgic.vgic_cpu_base = VGIC_ADDR_UNDEF;
		return -EINVAL;
	}

	mutex_unlock(&kvm->lock);
	return r;
}
