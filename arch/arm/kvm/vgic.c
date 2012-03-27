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
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_irq.h>

#include <asm/kvm_emulate.h>
#include <asm/hardware/gic.h>
#include <asm/kvm_arm.h>
#include <asm/kvm_mmu.h>

/*
 * How the whole thing works (courtesy of Christoffer Dall):
 *
 * - At any time, the dist->irq_pending_on_cpu is the oracle that knows if
 *   something is pending
 * - VGIC pending interrupts are stored on the vgic.irq_state vgic
 *   bitmap (this bitmap is updated by both user land ioctls and guest
 *   mmio ops) and indicate the 'wire' state.
 * - Every time the bitmap changes, the irq_pending_on_cpu oracle is
 *   recalculated
 * - To calculate the oracle, we need info for each cpu from
 *   compute_pending_for_cpu, which considers:
 *   - PPI: dist->irq_state & dist->irq_enable
 *   - SPI: dist->irq_state & dist->irq_enable & dist->irq_spi_target
 *   - irq_spi_target is a 'formatted' of the GICD_ICFGR registers,
 *     stored on each vcpu. We only keep one bit of information per
 *     interrupt, making sure that only one vcpu can accept the
 *     interrupt.
 *
 * The handling of level interrupts adds some extra complexity. We
 * need to track when the interrupt has been EOIed, so we can sample
 * the 'line' again. This is achieve as such:
 *
 * - When a level interrupt in moved onto a vcpu, the corresponding
 *   bit in irq_active is set. As long as this bit is set, the line
 *   will be ignored for further interrupts. The interrupt is injected
 *   into the vcpu with the VGIC_LR_EOI bit set (generate a
 *   maintainance interrupt on EOI).
 * - When the interrupt is EOIed, the maintainance interrupt fires,
 *   and clears the corresponding bit in irq_active. This allow the
 *   interrupt line to be sampled again.
 */

/* Temporary hacks, need to be provided by userspace emulation */
#define VGIC_DIST_BASE		0x2c001000
#define VGIC_DIST_SIZE		0x1000
#define VGIC_CPU_BASE		0x2c002000
#define VGIC_CPU_SIZE		0x2000

/* Virtual control interface base address */
static void __iomem *vgic_vctrl_base;

static struct device_node *vgic_node;

#define ACCESS_READ_VALUE	(1 << 0)
#define ACCESS_READ_RAZ		(0 << 0)
#define ACCESS_READ_MASK(x)	((x) & (1 << 0))
#define ACCESS_WRITE_IGNORED	(0 << 1)
#define ACCESS_WRITE_SETBIT	(1 << 1)
#define ACCESS_WRITE_CLEARBIT	(2 << 1)
#define ACCESS_WRITE_VALUE	(3 << 1)
#define ACCESS_WRITE_MASK(x)	((x) & (3 << 1))

static void vgic_update_state(struct kvm *kvm);
static void vgic_kick_vcpus(struct kvm *kvm);
static void vgic_dispatch_sgi(struct kvm_vcpu *vcpu, u32 reg);

static inline int vgic_irq_is_edge(struct vgic_dist *dist, int irq)
{
	return vgic_bitmap_get_irq_val(&dist->irq_cfg, 0, irq);
}

static void vgic_reg_access(struct kvm_exit_mmio *mmio, u32 *reg, u32 offset, int mode)
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

	if (mmio->mmio.is_write) {
		u32 data = (*((u32 *)mmio->mmio.data) & mask) << shift;
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
			*((u32 *)mmio->mmio.data) = (regval >> shift) & mask;
		}
	}
}

static void handle_mmio_misc(struct kvm_vcpu *vcpu,
			     struct kvm_exit_mmio *mmio, u32 offset)
{
	u32 reg;
	u32 u32off = offset & 3;

	switch (offset & ~3) {
	case 0:			/* CTLR */
		reg = vcpu->kvm->arch.vgic.enabled;
		vgic_reg_access(mmio, &reg, u32off,
				ACCESS_READ_VALUE | ACCESS_WRITE_VALUE);
		if (mmio->mmio.is_write) {
			vcpu->kvm->arch.vgic.enabled = reg & 1;
			vgic_update_state(vcpu->kvm);
		}
		break;

	case 4:			/* TYPER */
		reg  = (atomic_read(&vcpu->kvm->online_vcpus) - 1) << 5;
		reg |= (VGIC_NR_IRQS >> 5) - 1;
		vgic_reg_access(mmio, &reg, u32off,
				ACCESS_READ_VALUE | ACCESS_WRITE_IGNORED);
		break;

	case 8:			/* IIDR */
		reg = 0x4B00043B;
		vgic_reg_access(mmio, &reg, u32off,
				ACCESS_READ_VALUE | ACCESS_WRITE_IGNORED);
		break;
	}
}

static void handle_mmio_raz_wi(struct kvm_vcpu *vcpu,
			       struct kvm_exit_mmio *mmio, u32 offset)
{
	vgic_reg_access(mmio, NULL, offset,
			ACCESS_READ_RAZ | ACCESS_WRITE_IGNORED);
}

static void handle_mmio_set_enable_reg(struct kvm_vcpu *vcpu,
				       struct kvm_exit_mmio *mmio, u32 offset)
{
	u32 *reg = vgic_bitmap_get_reg(&vcpu->kvm->arch.vgic.irq_enabled,
				       vcpu->vcpu_id, offset);
	vgic_reg_access(mmio, reg, offset,
			ACCESS_READ_VALUE | ACCESS_WRITE_SETBIT);
	if (mmio->mmio.is_write)
		vgic_update_state(vcpu->kvm);
}

static void handle_mmio_clear_enable_reg(struct kvm_vcpu *vcpu,
					 struct kvm_exit_mmio *mmio, u32 offset)
{
	u32 *reg = vgic_bitmap_get_reg(&vcpu->kvm->arch.vgic.irq_enabled,
				       vcpu->vcpu_id, offset);
	vgic_reg_access(mmio, reg, offset,
			ACCESS_READ_VALUE | ACCESS_WRITE_CLEARBIT);
	if (mmio->mmio.is_write) {
		if (offset < 4) /* Force SGI enabled */
			*reg |= 0xffff;
		vgic_update_state(vcpu->kvm);
	}
}

static void handle_mmio_set_pending_reg(struct kvm_vcpu *vcpu,
					struct kvm_exit_mmio *mmio, u32 offset)
{
	u32 *reg = vgic_bitmap_get_reg(&vcpu->kvm->arch.vgic.irq_state,
				       vcpu->vcpu_id, offset);
	vgic_reg_access(mmio, reg, offset,
			ACCESS_READ_VALUE | ACCESS_WRITE_SETBIT);
	if (mmio->mmio.is_write)
		vgic_update_state(vcpu->kvm);
}

static void handle_mmio_clear_pending_reg(struct kvm_vcpu *vcpu,
					  struct kvm_exit_mmio *mmio, u32 offset)
{
	u32 *reg = vgic_bitmap_get_reg(&vcpu->kvm->arch.vgic.irq_state,
				       vcpu->vcpu_id, offset);
	vgic_reg_access(mmio, reg, offset,
			ACCESS_READ_VALUE | ACCESS_WRITE_CLEARBIT);
	if (mmio->mmio.is_write)
		vgic_update_state(vcpu->kvm);
}

static void handle_mmio_priority_reg(struct kvm_vcpu *vcpu,
				     struct kvm_exit_mmio *mmio, u32 offset)
{
	u32 *reg = vgic_bytemap_get_reg(&vcpu->kvm->arch.vgic.irq_priority,
					vcpu->vcpu_id, offset);
	vgic_reg_access(mmio, reg, offset,
			ACCESS_READ_VALUE | ACCESS_WRITE_VALUE);
}

static u32 vgic_get_target_reg(struct kvm *kvm, int irq)
{
	struct vgic_dist *dist = &kvm->arch.vgic;
	struct kvm_vcpu *vcpu;
	int i, c;
	unsigned long *bmap;
	u32 val = 0;

	BUG_ON(irq & 3);
	BUG_ON(irq < 32);

	irq -= 32;

	kvm_for_each_vcpu(c, vcpu, kvm) {	
		bmap = vgic_bitmap_get_shared_map(&dist->irq_spi_target[c]);
		for (i = 0; i < 4; i++)
			if (test_bit(irq + i, bmap))
				val |= 1 << (c + i * 8);
	}

	return val;
}

static void vgic_set_target_reg(struct kvm *kvm, u32 val, int irq)
{
	struct vgic_dist *dist = &kvm->arch.vgic;
	struct kvm_vcpu *vcpu;
	int i, c;
	unsigned long *bmap;
	u32 target;

	BUG_ON(irq & 3);
	BUG_ON(irq < 32);

	irq -= 32;

	/*
	 * Pick the LSB in each byte. This ensure we only target one
	 * single vcpu per IRQ. If the byte is null, assume we target
	 * CPU0.
	 */
	for (i = 0; i < 32; i += 8) {
		target = ffs(val & (0xffU << i));
		val &= ~(0xffU << i);
		val |= 1 << (target ? (target - 1) : i);
	}

	kvm_for_each_vcpu(c, vcpu, kvm) {
		bmap = vgic_bitmap_get_shared_map(&dist->irq_spi_target[c]);
		for (i = 0; i < 4; i++) {
			if (val & (1 << (c + i * 8)))
				set_bit(irq + i, bmap);
			else
				clear_bit(irq + i, bmap);
		}
	}
}

static void handle_mmio_target_reg(struct kvm_vcpu *vcpu,
				   struct kvm_exit_mmio *mmio, u32 offset)
{
	u32 reg;

	/* We treat the banked interrupts targets as read-only */
	if (offset < 32) {
		u32 roreg = 1 << vcpu->vcpu_id;
		roreg |= roreg << 8;
		roreg |= roreg << 16;

		vgic_reg_access(mmio, &roreg, offset,
				ACCESS_READ_VALUE | ACCESS_WRITE_IGNORED);
		return;
	}

	reg = vgic_get_target_reg(vcpu->kvm, offset & ~3U);
	vgic_reg_access(mmio, &reg, offset,
			ACCESS_READ_VALUE | ACCESS_WRITE_VALUE);
	if (mmio->mmio.is_write) {
		vgic_set_target_reg(vcpu->kvm, reg, offset & ~3U);
		vgic_update_state(vcpu->kvm);
	}
}

static u32 vgic_cfg_expand(u16 val)
{
	u32 res = 0;
	int i;

	for (i = 0; i < 16; i++)
		res |= (val >> i) << (2 * i + 1);

	return res;
}

static u16 vgic_cfg_compress(u32 val)
{
	u16 res = 0;
	int i;

	for (i = 0; i < 16; i++)
		res |= (val >> (i * 2 + 1)) << i;

	return res;
}

/*
 * The distributor uses 2 bits per IRQ for the CFG register, but the
 * LSB is always 0. As such, we only keep the upper bit, and use the
 * two above functions to compress/expand the bits
 */
static void handle_mmio_cfg_reg(struct kvm_vcpu *vcpu,
				struct kvm_exit_mmio *mmio, u32 offset)
{
	u32 val;
	u32 *reg = vgic_bitmap_get_reg(&vcpu->kvm->arch.vgic.irq_cfg,
				       vcpu->vcpu_id, offset >> 1);
	if (offset & 2)
		val = *reg >> 16;
	else
		val = *reg & 0xffff;

	val = vgic_cfg_expand(val);
	vgic_reg_access(mmio, &val, offset,
			ACCESS_READ_VALUE | ACCESS_WRITE_VALUE);
	if (mmio->mmio.is_write) {
		if (offset < 4) {
			*reg = ~0U; /* Force PPIs/SGIs to 1 */
			return;
		}

		val = vgic_cfg_compress(val);
		if (offset & 2) {
			*reg &= 0xffff;
			*reg |= val << 16;
		} else {
			*reg &= 0xffff << 16;
			*reg |= val;
		}
	}
}

static void handle_mmio_sgi_reg(struct kvm_vcpu *vcpu,
				struct kvm_exit_mmio *mmio, u32 offset)
{
	u32 reg;
	vgic_reg_access(mmio, &reg, offset,
			ACCESS_READ_RAZ | ACCESS_WRITE_VALUE);
	if (mmio->mmio.is_write) {
		vgic_dispatch_sgi(vcpu, reg);
		vgic_update_state(vcpu->kvm);
	}
}

/* All this should be handled by kvm_bus_io_*()... FIXME!!! */
struct mmio_range {
	unsigned long base;
	unsigned long len;
	void (*handle_mmio)(struct kvm_vcpu *vcpu, struct kvm_exit_mmio *mmio,
			    u32 offset);
};

static const struct mmio_range vgic_ranges[] = {
	{			/* CTRL, TYPER, IIDR */
		.base		= 0,
		.len		= 12,
		.handle_mmio	= handle_mmio_misc,
	},
	{			/* IGROUPRn */
		.base		= 0x80,
		.len		= VGIC_NR_IRQS / 8,
		.handle_mmio	= handle_mmio_raz_wi,
	},
	{			/* ISENABLERn */
		.base		= 0x100,
		.len		= VGIC_NR_IRQS / 8,
		.handle_mmio	= handle_mmio_set_enable_reg,
	},
	{			/* ICENABLERn */
		.base		= 0x180,
		.len		= VGIC_NR_IRQS / 8,
		.handle_mmio	= handle_mmio_clear_enable_reg,
	},
	{			/* ISPENDRn */
		.base		= 0x200,
		.len		= VGIC_NR_IRQS / 8,
		.handle_mmio	= handle_mmio_set_pending_reg,
	},
	{			/* ICPENDRn */
		.base		= 0x280,
		.len		= VGIC_NR_IRQS / 8,
		.handle_mmio	= handle_mmio_clear_pending_reg,
	},
	{			/* ISACTIVERn */
		.base		= 0x300,
		.len		= VGIC_NR_IRQS / 8,
		.handle_mmio	= handle_mmio_raz_wi,
	},
	{			/* ICACTIVERn */
		.base		= 0x380,
		.len		= VGIC_NR_IRQS / 8,
		.handle_mmio	= handle_mmio_raz_wi,
	},
	{			/* IPRIORITYRn */
		.base		= 0x400,
		.len		= VGIC_NR_IRQS,
		.handle_mmio	= handle_mmio_priority_reg,
	},
	{			/* ITARGETSRn */
		.base		= 0x800,
		.len		= VGIC_NR_IRQS,
		.handle_mmio	= handle_mmio_target_reg,
	},
	{			/* ICFGRn */
		.base		= 0xC00,
		.len		= VGIC_NR_IRQS / 4,
		.handle_mmio	= handle_mmio_cfg_reg,
	},
	{			/* SGIRn */
		.base		= 0xF00,
		.len		= 4,
		.handle_mmio	= handle_mmio_sgi_reg,
	},
	{}
};

static const
struct mmio_range *find_matching_range(const struct mmio_range *ranges,
				       struct kvm_exit_mmio *mmio,
				       unsigned long base)
{
	const struct mmio_range *r = ranges;
	unsigned long addr = mmio->mmio.phys_addr - base;

	while (r->len) {
		if (addr >= r->base &&
		    (addr + mmio->mmio.len) <= (r->base + r->len))
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
 * returns KVM_EXIT_UNKNOWN if the MMIO access has been performed
 * in kernel space, and KVM_EXIT_MMIO if it needs to be emulated
 * in user space.
 */
int vgic_handle_mmio(struct kvm_vcpu *vcpu, struct kvm_run *run, struct kvm_exit_mmio *mmio)
{
	const struct mmio_range *range;
	struct vgic_dist *dist = &vcpu->kvm->arch.vgic;
	unsigned long base = dist->vgic_dist_base;

	if (!irqchip_in_kernel(vcpu->kvm) ||
	    mmio->mmio.phys_addr < base ||
	    (mmio->mmio.phys_addr + mmio->mmio.len) > (base + dist->vgic_dist_size))
		return KVM_EXIT_MMIO;

	range = find_matching_range(vgic_ranges, mmio, base);
	if (unlikely(!range || !range->handle_mmio)) {
		pr_warn("Unhandled access %d %08llx %d\n",
			mmio->mmio.is_write, mmio->mmio.phys_addr, mmio->mmio.len);
		return KVM_EXIT_MMIO;
	}

	spin_lock(&vcpu->kvm->arch.vgic.lock);
	kvm_debug("emulating %d %08llx %d\n", mmio->mmio.is_write,
		  mmio->mmio.phys_addr, mmio->mmio.len);
	range->handle_mmio(vcpu, mmio, mmio->mmio.phys_addr - range->base - base);
	run->mmio = mmio->mmio;
	kvm_handle_mmio_return(vcpu, run);
	spin_unlock(&vcpu->kvm->arch.vgic.lock);

	vgic_kick_vcpus(vcpu->kvm);

	return KVM_EXIT_UNKNOWN;
}

static void vgic_dispatch_sgi(struct kvm_vcpu *vcpu, u32 reg)
{
	struct kvm *kvm = vcpu->kvm;
	struct vgic_dist *dist = &kvm->arch.vgic;
	int nrcpus = atomic_read(&kvm->online_vcpus);
	u8 target_cpus;
	int sgi, mode, c, vcpu_id;

	vcpu_id = vcpu->vcpu_id;

	sgi = reg & 0xf;
	target_cpus = (reg >> 16) & 0xff;
	mode = (reg >> 24) & 3;

	switch (mode) {
	case 0:
		if (!target_cpus)
			return;

	case 1:
		target_cpus = ((1 << nrcpus) - 1) & ~(1 << vcpu_id) & 0xff;
		break;

	case 2:
		target_cpus = 1 << vcpu_id;
		break;
	}

	kvm_for_each_vcpu(c, vcpu, kvm) {
		if (target_cpus & 1) {
			/* Flag the SGI as pending */
			vgic_bitmap_set_irq_val(&dist->irq_state, c, sgi, 1);
			dist->irq_sgi_sources[c][sgi] |= 1 << vcpu_id;
			kvm_debug("SGI%d from CPU%d to CPU%d\n", sgi, vcpu_id, c);
		}

		target_cpus >>= 1;
	}
}

static int compute_pending_for_cpu(struct kvm_vcpu *vcpu)
{
	struct vgic_dist *dist = &vcpu->kvm->arch.vgic;
	unsigned long *pending, *enabled, *pend;
	int vcpu_id;

	vcpu_id = vcpu->vcpu_id;
	pend = vcpu->arch.vgic_cpu.pending;

	pending = vgic_bitmap_get_cpu_map(&dist->irq_state, vcpu_id);
	enabled = vgic_bitmap_get_cpu_map(&dist->irq_enabled, vcpu_id);
	bitmap_and(pend, pending, enabled, 32);
	
	pending = vgic_bitmap_get_shared_map(&dist->irq_state);
	enabled = vgic_bitmap_get_shared_map(&dist->irq_enabled);
	bitmap_and(pend + 1, pending, enabled, VGIC_NR_SHARED_IRQS);
	bitmap_and(pend + 1, pend + 1,
		   vgic_bitmap_get_shared_map(&dist->irq_spi_target[vcpu_id]),
		   VGIC_NR_SHARED_IRQS);

	return (find_first_bit(pend, VGIC_NR_IRQS) < VGIC_NR_IRQS);
}

/*
 * Update the interrupt state and determine which CPUs have pending
 * interrupts. Must be called with distributor lock held.
 */
static void vgic_update_state(struct kvm *kvm)
{
	struct vgic_dist *dist = &kvm->arch.vgic;
	struct kvm_vcpu *vcpu;
	int c;

	if (!dist->enabled) {
		set_bit(0, &dist->irq_pending_on_cpu);
		return;
	}

	kvm_for_each_vcpu(c, vcpu, kvm) {
		if (compute_pending_for_cpu(vcpu)) {
			pr_debug("CPU%d has pending interrupts\n", c);
			set_bit(1 << c, &dist->irq_pending_on_cpu);
		}
	}
}

/*
 * Queue an interrupt to a CPU virtual interface. Return 0 on success,
 * or 1 if it wasn't possible to queue it.
 */
static int vgic_queue_irq(struct kvm_vcpu *vcpu, u8 sgi_source_id, int irq)
{
	struct vgic_cpu *vgic_cpu = &vcpu->arch.vgic_cpu;
	struct vgic_dist *dist = &vcpu->kvm->arch.vgic;
	int lr, is_level;

	/* Sanitize the input... */
	BUG_ON(sgi_source_id & ~7);
	BUG_ON(sgi_source_id && irq > 15);
	BUG_ON(irq >= VGIC_NR_IRQS);

	kvm_debug("Queue IRQ%d\n", irq);

	lr = vgic_cpu->vgic_irq_lr_map[irq];
	is_level = !vgic_irq_is_edge(dist, irq);

	/* Do we have an active interrupt for the same CPUID? */
	if (lr != LR_EMPTY &&
	    (vgic_cpu->vgic_lr[lr] & VGIC_LR_PHYSID_CPUID) == (sgi_source_id << 10)) {
		kvm_debug("LR%d piggyback for IRQ%d %x\n", lr, irq, vgic_cpu->vgic_lr[lr]);
		BUG_ON(!test_bit(lr, vgic_cpu->lr_used));
		vgic_cpu->vgic_lr[lr] |= VGIC_LR_PENDING_BIT;
		if (is_level)
			vgic_cpu->vgic_lr[lr] |= VGIC_LR_EOI;
		return 0;
	}

	/* Try to use another LR for this interrupt */
	lr = find_first_bit((unsigned long *)vgic_cpu->vgic_elrsr,
			       vgic_cpu->nr_lr);
	if (lr >= vgic_cpu->nr_lr)
		return 1;

	kvm_debug("LR%d allocated for IRQ%d %x\n", lr, irq, sgi_source_id);
	vgic_cpu->vgic_lr[lr] = (VGIC_LR_PENDING_BIT |  (sgi_source_id << 10) | irq);
	if (is_level)
		vgic_cpu->vgic_lr[lr] |= VGIC_LR_EOI;

	vgic_cpu->vgic_irq_lr_map[irq] = lr;
	clear_bit(lr, (unsigned long *)vgic_cpu->vgic_elrsr);
	set_bit(lr, vgic_cpu->lr_used);

	return 0;
}

/*
 * Fill the list registers with pending interrupts before running the
 * guest.
 */
static void __kvm_vgic_sync_to_cpu(struct kvm_vcpu *vcpu)
{
	struct vgic_cpu *vgic_cpu = &vcpu->arch.vgic_cpu;
	struct vgic_dist *dist = &vcpu->kvm->arch.vgic;
	unsigned long *pending;
	int i, c, vcpu_id;
	int overflow = 0;

	vcpu_id = vcpu->vcpu_id;

	/*
	 * We may not have any pending interrupt, or the interrupts
	 * may have been serviced from another vcpu. In all cases,
	 * move along.
	 */
	if (!kvm_vgic_vcpu_pending_irq(vcpu)) {
		pr_debug("CPU%d has no pending interrupt\n", vcpu_id);
		goto epilog;
	}

	/* SGIs */
	pending = vgic_bitmap_get_cpu_map(&dist->irq_state, vcpu_id);
	for_each_set_bit(i, vgic_cpu->pending, 16) {
		unsigned long sources;

		pr_debug("SGI%d on CPU%d\n", i, vcpu_id);
		sources = dist->irq_sgi_sources[vcpu_id][i];
		for_each_set_bit(c, &sources, 8) {
			if (vgic_queue_irq(vcpu, c, i)) {
				overflow = 1;
				continue;
			}

			sources &= ~(1 << c);
		}

		if (!sources)
			clear_bit(i, pending);

		dist->irq_sgi_sources[vcpu_id][i] = sources;
	}

	/* PPIs */
	for_each_set_bit_from(i, vgic_cpu->pending, 32) {
		if (vgic_queue_irq(vcpu, 0, i)) {
			overflow = 1;
			continue;
		}

		clear_bit(i, pending);
	}

	
	/* SPIs */
	pending = vgic_bitmap_get_shared_map(&dist->irq_state);
	for_each_set_bit_from(i, vgic_cpu->pending, VGIC_NR_IRQS) {
		if (vgic_bitmap_get_irq_val(&dist->irq_active, 0, i))
			continue; /* level interrupt, already queued */

		if (vgic_queue_irq(vcpu, 0, i)) {
			overflow = 1;
			continue;
		}

		/* Immediate clear on edge, set active on level */
		if (vgic_irq_is_edge(dist, i))
			clear_bit(i - 32, pending);
		else
			vgic_bitmap_set_irq_val(&dist->irq_active, 0, i, 1);
	}

epilog:
	if (overflow)
		vgic_cpu->vgic_hcr |= VGIC_HCR_UIE;
	else {
		vgic_cpu->vgic_hcr &= ~VGIC_HCR_UIE;
		/*
		 * We're about to run this VCPU, and we've consumed
		 * everything the distributor had in store for
		 * us. Claim we don't have anything pending. We'll
		 * adjust that if needed while exiting.
		 */
		clear_bit(1 << vcpu_id, &dist->irq_pending_on_cpu);
	}
}

/*
 * Sync back the VGIC state after a guest run.
 */
static void __kvm_vgic_sync_from_cpu(struct kvm_vcpu *vcpu)
{
	struct vgic_cpu *vgic_cpu = &vcpu->arch.vgic_cpu;
	struct vgic_dist *dist = &vcpu->kvm->arch.vgic;
	int lr, pending;

	/* Clear mappings for empty LRs */
	for_each_set_bit(lr, (unsigned long *)vgic_cpu->vgic_elrsr,
			 vgic_cpu->nr_lr) {
		int irq;

		if (!test_and_clear_bit(lr, vgic_cpu->lr_used))
			continue;

		irq = vgic_cpu->vgic_lr[lr] & VGIC_LR_VIRTUALID;

		BUG_ON(irq >= VGIC_NR_IRQS);
		vgic_cpu->vgic_irq_lr_map[irq] = LR_EMPTY;
	}

	/* Check if we still have something up our sleeve... */
	pending = find_first_zero_bit((unsigned long *)vgic_cpu->vgic_elrsr,
				      vgic_cpu->nr_lr);
	if (pending < vgic_cpu->nr_lr)
		set_bit(1 << vcpu->vcpu_id, &dist->irq_pending_on_cpu);
}

void kvm_vgic_sync_to_cpu(struct kvm_vcpu *vcpu)
{
	struct vgic_dist *dist = &vcpu->kvm->arch.vgic;

	if (!irqchip_in_kernel(vcpu->kvm))
		return;

	spin_lock(&dist->lock);
	__kvm_vgic_sync_to_cpu(vcpu);
	spin_unlock(&dist->lock);
}	

void kvm_vgic_sync_from_cpu(struct kvm_vcpu *vcpu)
{
	struct vgic_dist *dist = &vcpu->kvm->arch.vgic;

	if (!irqchip_in_kernel(vcpu->kvm))
		return;

	spin_lock(&dist->lock);
	__kvm_vgic_sync_from_cpu(vcpu);
	spin_unlock(&dist->lock);
}

int kvm_vgic_vcpu_pending_irq(struct kvm_vcpu *vcpu)
{
	struct vgic_dist *dist = &vcpu->kvm->arch.vgic;

	if (!irqchip_in_kernel(vcpu->kvm))
		return 0;

	return test_bit(1 << vcpu->vcpu_id, &dist->irq_pending_on_cpu);
}

static void vgic_kick_vcpus(struct kvm *kvm)
{
	struct kvm_vcpu *vcpu;
	int c;

	/*
	 * We've injected an interrupt, time to find out who deserves
	 * a good kick...
	 */
	kvm_for_each_vcpu(c, vcpu, kvm) {
		if (kvm_vgic_vcpu_pending_irq(vcpu)) {
			vcpu->arch.wait_for_interrupts = 0;
			kvm_vcpu_kick(vcpu);
		}
	}
}

int kvm_vgic_inject_irq(struct kvm *kvm, int cpuid, const struct kvm_irq_level *irq)
{
	struct vgic_dist *dist = &kvm->arch.vgic;
	int nrcpus = atomic_read(&kvm->online_vcpus);
	int is_edge, state;

	if (cpuid >= nrcpus)
		return -EINVAL;

	/* Only PPIs or SPIs */
	if (irq->irq >= VGIC_NR_IRQS || irq->irq < 16)
		return -EINVAL;

	kvm_debug("Inject IRQ%d\n", irq->irq);
	spin_lock(&dist->lock);
	is_edge = vgic_irq_is_edge(dist, irq->irq);
	state = vgic_bitmap_get_irq_val(&dist->irq_state, cpuid, irq->irq);

	/*
	 * Inject an interrupt if:
	 * - level triggered and we change level
	 * - edge triggered and we have a rising edge
	 */
	if ((!is_edge && (state ^ !!irq->level)) ||
	    (is_edge && !state && irq->level)) {
		vgic_bitmap_set_irq_val(&dist->irq_state, cpuid,
					irq->irq, !!irq->level);
		vgic_update_state(kvm);
	}
	spin_unlock(&dist->lock);

	vgic_kick_vcpus(kvm);

	return 0;
}

static irqreturn_t vgic_maintainance_handler(int irq, void *data)
{
	struct kvm_vcpu *vcpu = *(struct kvm_vcpu **)data;
	struct vgic_dist *dist;
	struct vgic_cpu *vgic_cpu;

	if (WARN(!vcpu,
		 "VGIC interrupt on CPU %d with no vcpu\n", smp_processor_id()))
		return IRQ_HANDLED;

	vgic_cpu = &vcpu->arch.vgic_cpu;
	dist = &vcpu->kvm->arch.vgic;
	kvm_debug("MISR = %08x\n", vgic_cpu->vgic_misr);

	if (vgic_cpu->vgic_misr & VGIC_MISR_EOI) {
		/*
		 * Some level interrupts have been EOIed. Clear their
		 * active bit.
		 */
		int lr, irq;

		spin_lock(&dist->lock);
		for_each_set_bit(lr, (unsigned long *)vgic_cpu->vgic_eisr,
				 vgic_cpu->nr_lr) {
			irq = vgic_cpu->vgic_lr[lr] & VGIC_LR_VIRTUALID;
			
			vgic_bitmap_set_irq_val(&dist->irq_active,
						vcpu->vcpu_id, irq, 0);
			vgic_cpu->vgic_lr[lr] &= ~VGIC_LR_EOI;
			writel_relaxed(vgic_cpu->vgic_lr[lr],
				       dist->vctrl_base + GICH_LR0 + (lr << 2));
		}
		spin_unlock(&dist->lock);
	}

	if (vgic_cpu->vgic_misr & VGIC_MISR_U) {
		vgic_cpu->vgic_hcr &= ~VGIC_HCR_UIE;
		writel_relaxed(vgic_cpu->vgic_hcr, dist->vctrl_base + GICH_HCR);
	}

	return IRQ_HANDLED;
}

void kvm_vgic_vcpu_init(struct kvm_vcpu *vcpu)
{
	struct vgic_cpu *vgic_cpu = &vcpu->arch.vgic_cpu;
	struct vgic_dist *dist = &vcpu->kvm->arch.vgic;
	u32 reg;
	int i;

	if (!irqchip_in_kernel(vcpu->kvm))
		return;

	for (i = 0; i < VGIC_NR_IRQS; i++) {
		if (i < 16)
			vgic_bitmap_set_irq_val(&dist->irq_enabled,
						vcpu->vcpu_id, i, 1);
		if (i < 32)
			vgic_bitmap_set_irq_val(&dist->irq_cfg,
						vcpu->vcpu_id, i, 1);

		vgic_cpu->vgic_irq_lr_map[i] = LR_EMPTY;
	}

	BUG_ON(!vcpu->kvm->arch.vgic.vctrl_base);
	reg = readl_relaxed(vcpu->kvm->arch.vgic.vctrl_base + GICH_VTR);
	vgic_cpu->nr_lr = (reg & 0x1f) + 1;

	reg = readl_relaxed(vcpu->kvm->arch.vgic.vctrl_base + GICH_VMCR);
	vgic_cpu->vgic_vmcr = reg | (0x1f << 27); /* Priority */

	vgic_cpu->vgic_hcr |= VGIC_HCR_EN; /* Get the show on the road... */
}

static void vgic_init_maintainance_interrupt(void *info)
{
	unsigned int *irqp = info;

	enable_percpu_irq(*irqp, 0);
}

int kvm_vgic_hyp_init(void)
{
	int ret;
	unsigned int irq;
	struct resource vctrl_res;

	vgic_node = of_find_compatible_node(NULL, NULL, "arm,cortex-a15-gic");
	if (!vgic_node)
		return -ENODEV;

	irq = irq_of_parse_and_map(vgic_node, 0);
	if (!irq)
		return -ENXIO;

	ret = request_percpu_irq(irq, vgic_maintainance_handler,
				 "vgic", kvm_get_running_vcpus());
	if (ret) {
		kvm_err("Cannot register interrupt %d\n", irq);
		return ret;
	}
	
	ret = of_address_to_resource(vgic_node, 2, &vctrl_res);
	if (ret) {
		kvm_err("Cannot obtain VCTRL resource\n");
		goto out_free_irq;
	}

	vgic_vctrl_base = of_iomap(vgic_node, 2);
	if (!vgic_vctrl_base) {
		kvm_err("Cannot ioremap VCTRL\n");
		ret = -ENOMEM;
		goto out_free_irq;
	}

	ret = create_hyp_io_mappings(vgic_vctrl_base,
				     vgic_vctrl_base + resource_size(&vctrl_res),
				     vctrl_res.start);
	if (ret) {
		kvm_err("Cannot map VCTRL into hyp\n");
		goto out_unmap;
	}

	kvm_info("%s@%llx IRQ%d\n", vgic_node->name, vctrl_res.start, irq);
	on_each_cpu(vgic_init_maintainance_interrupt, &irq, 1);

	return 0;

out_unmap:
	iounmap(vgic_vctrl_base);	
out_free_irq:
	free_percpu_irq(irq, kvm_get_running_vcpus());

	return ret;
}

int kvm_vgic_init(struct kvm *kvm)
{
	int ret, i;
	struct resource vcpu_res;

	mutex_lock(&kvm->lock);

	if (of_address_to_resource(vgic_node, 3, &vcpu_res)) {
		kvm_err("Cannot obtain VCPU resource\n");
		ret = -ENXIO;
		goto out;
	}

	if (atomic_read(&kvm->online_vcpus) || kvm->arch.vgic.vctrl_base) {
		ret = -EEXIST;
		goto out;
	}

	spin_lock_init(&kvm->arch.vgic.lock);
	kvm->arch.vgic.vctrl_base = vgic_vctrl_base;
	kvm->arch.vgic.vgic_dist_base = VGIC_DIST_BASE;
	kvm->arch.vgic.vgic_dist_size = VGIC_DIST_SIZE;

	ret = kvm_phys_addr_ioremap(kvm, VGIC_CPU_BASE,
				    vcpu_res.start, VGIC_CPU_SIZE);
	if (ret) {
		kvm_err("Unable to remap VGIC CPU to VCPU\n");
		goto out;
	}

	for (i = 32; i < VGIC_NR_IRQS; i += 4)
		vgic_set_target_reg(kvm, 0, i);

out:
	mutex_unlock(&kvm->lock);
	return ret;
}
