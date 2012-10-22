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

#ifndef __ASM_ARM_KVM_VGIC_H
#define __ASM_ARM_KVM_VGIC_H

#include <linux/kernel.h>
#include <linux/kvm.h>
#include <linux/kvm_host.h>
#include <linux/irqreturn.h>
#include <linux/spinlock.h>
#include <linux/types.h>

#define VGIC_NR_IRQS		128
#define VGIC_NR_SHARED_IRQS	(VGIC_NR_IRQS - 32)
#define VGIC_MAX_CPUS		NR_CPUS

/* Sanity checks... */
#if (VGIC_MAX_CPUS > 8)
#error	Invalid number of CPU interfaces
#endif

#if (VGIC_NR_IRQS & 31)
#error "VGIC_NR_IRQS must be a multiple of 32"
#endif

#if (VGIC_NR_IRQS > 1024)
#error "VGIC_NR_IRQS must be <= 1024"
#endif

/*
 * The GIC distributor registers describing interrupts have two parts:
 * - 32 per-CPU interrupts (SGI + PPI)
 * - a bunch of shared interrups (SPI)
 */
struct vgic_bitmap {
	union {
		u32 reg[1];
		unsigned long reg_ul[0];
	} percpu[VGIC_MAX_CPUS];
	union {
		u32 reg[VGIC_NR_SHARED_IRQS / 32];
		unsigned long reg_ul[0];
	} shared;
};

static inline u32 *vgic_bitmap_get_reg(struct vgic_bitmap *x,
				       int cpuid, u32 offset)
{
	offset >>= 2;
	BUG_ON(offset > (VGIC_NR_IRQS / 32));
	if (!offset)
		return x->percpu[cpuid].reg;
	else
		return x->shared.reg + offset - 1;
}

static inline int vgic_bitmap_get_irq_val(struct vgic_bitmap *x,
					 int cpuid, int irq)
{
	if (irq < 32)
		return test_bit(irq, x->percpu[cpuid].reg_ul);

	return test_bit(irq - 32, x->shared.reg_ul);
}

static inline void vgic_bitmap_set_irq_val(struct vgic_bitmap *x,
					   int cpuid, int irq, int val)
{
	unsigned long *reg;

	if (irq < 32)
		reg = x->percpu[cpuid].reg_ul;
	else {
		reg =  x->shared.reg_ul;
		irq -= 32;
	}

	if (val)
		set_bit(irq, reg);
	else
		clear_bit(irq, reg);
}

static inline unsigned long *vgic_bitmap_get_cpu_map(struct vgic_bitmap *x,
						     int cpuid)
{
	if (unlikely(cpuid >= VGIC_MAX_CPUS))
		return NULL;
	return x->percpu[cpuid].reg_ul;
}

static inline unsigned long *vgic_bitmap_get_shared_map(struct vgic_bitmap *x)
{
	return x->shared.reg_ul;
}

struct vgic_bytemap {
	union {
		u32 reg[8];
		unsigned long reg_ul[0];
	} percpu[VGIC_MAX_CPUS];
	union {
		u32 reg[VGIC_NR_SHARED_IRQS  / 4];
		unsigned long reg_ul[0];
	} shared;
};

static inline u32 *vgic_bytemap_get_reg(struct vgic_bytemap *x,
					int cpuid, u32 offset)
{
	offset >>= 2;
	BUG_ON(offset > (VGIC_NR_IRQS / 4));
	if (offset < 4)
		return x->percpu[cpuid].reg + offset;
	else
		return x->shared.reg + offset - 8;
}

static inline int vgic_bytemap_get_irq_val(struct vgic_bytemap *x,
					   int cpuid, int irq)
{
	u32 *reg, shift;
	shift = (irq & 3) * 8;
	reg = vgic_bytemap_get_reg(x, cpuid, irq);
	return (*reg >> shift) & 0xff;
}

static inline void vgic_bytemap_set_irq_val(struct vgic_bytemap *x,
					    int cpuid, int irq, int val)
{
	u32 *reg, shift;
	shift = (irq & 3) * 8;
	reg = vgic_bytemap_get_reg(x, cpuid, irq);
	*reg &= ~(0xff << shift);
	*reg |= (val & 0xff) << shift;
}

struct vgic_dist {
#ifdef CONFIG_KVM_ARM_VGIC
	spinlock_t		lock;
	bool			ready;

	/* Virtual control interface mapping */
	void __iomem		*vctrl_base;

	/* Distributor and vcpu interface mapping in the guest */
	phys_addr_t		vgic_dist_base;
	phys_addr_t		vgic_cpu_base;

	/* Distributor enabled */
	u32			enabled;

	/* Interrupt enabled (one bit per IRQ) */
	struct vgic_bitmap	irq_enabled;

	/* Interrupt 'pin' level */
	struct vgic_bitmap	irq_state;

	/* Level-triggered interrupt in progress */
	struct vgic_bitmap	irq_active;

	/* Interrupt priority. Not used yet. */
	struct vgic_bytemap	irq_priority;

	/* Level/edge triggered */
	struct vgic_bitmap	irq_cfg;

	/* Source CPU per SGI and target CPU */
	u8			irq_sgi_sources[VGIC_MAX_CPUS][16];

	/* Target CPU for each IRQ */
	u8			irq_spi_cpu[VGIC_NR_SHARED_IRQS];
	struct vgic_bitmap	irq_spi_target[VGIC_MAX_CPUS];

	/* Bitmap indicating which CPU has something pending */
	unsigned long		irq_pending_on_cpu;
#endif
};

struct vgic_cpu {
#ifdef CONFIG_KVM_ARM_VGIC
	/* per IRQ to LR mapping */
	u8		vgic_irq_lr_map[VGIC_NR_IRQS];

	/* Pending interrupts on this VCPU */
	DECLARE_BITMAP(	pending, VGIC_NR_IRQS);

	/* Bitmap of used/free list registers */
	DECLARE_BITMAP(	lr_used, 64);

	/* Number of list registers on this CPU */
	int		nr_lr;

	/* CPU vif control registers for world switch */
	u32		vgic_hcr;
	u32		vgic_vmcr;
	u32		vgic_misr;	/* Saved only */
	u32		vgic_eisr[2];	/* Saved only */
	u32		vgic_elrsr[2];	/* Saved only */
	u32		vgic_apr;
	u32		vgic_lr[64];	/* A15 has only 4... */

	/* Number of level-triggered interrupt in progress */
	atomic_t	irq_active_count;
#endif
};

#define VGIC_HCR_EN		(1 << 0)
#define VGIC_HCR_UIE		(1 << 1)

#define VGIC_LR_VIRTUALID	(0x3ff << 0)
#define VGIC_LR_PHYSID_CPUID	(7 << 10)
#define VGIC_LR_STATE		(3 << 28)
#define VGIC_LR_PENDING_BIT	(1 << 28)
#define VGIC_LR_ACTIVE_BIT	(1 << 29)
#define VGIC_LR_EOI		(1 << 19)

#define VGIC_MISR_EOI		(1 << 0)
#define VGIC_MISR_U		(1 << 1)

#define LR_EMPTY	0xff

struct kvm;
struct kvm_vcpu;
struct kvm_run;
struct kvm_exit_mmio;

#ifdef CONFIG_KVM_ARM_VGIC
int kvm_vgic_set_addr(struct kvm *kvm, unsigned long type, u64 addr);
int kvm_vgic_hyp_init(void);
int kvm_vgic_init(struct kvm *kvm);
int kvm_vgic_create(struct kvm *kvm);
void kvm_vgic_vcpu_init(struct kvm_vcpu *vcpu);
void kvm_vgic_sync_to_cpu(struct kvm_vcpu *vcpu);
void kvm_vgic_sync_from_cpu(struct kvm_vcpu *vcpu);
int kvm_vgic_inject_irq(struct kvm *kvm, int cpuid, unsigned int irq_num,
			bool level);
int kvm_vgic_vcpu_pending_irq(struct kvm_vcpu *vcpu);
bool vgic_handle_mmio(struct kvm_vcpu *vcpu, struct kvm_run *run,
		      struct kvm_exit_mmio *mmio);

#define irqchip_in_kernel(k)	(!!((k)->arch.vgic.vctrl_base))
#define vgic_initialized(k)	((k)->arch.vgic.ready)
#define vgic_active_irq(v)	(atomic_read(&(v)->arch.vgic_cpu.irq_active_count) == 0)

#else
static inline int kvm_vgic_hyp_init(void)
{
	return 0;
}

static inline int kvm_vgic_set_addr(struct kvm *kvm, unsigned long type, u64 addr)
{
	return 0;
}

static inline int kvm_vgic_init(struct kvm *kvm)
{
	return 0;
}

static inline int kvm_vgic_create(struct kvm *kvm)
{
	return 0;
}

static inline void kvm_vgic_vcpu_init(struct kvm_vcpu *vcpu) {}
static inline void kvm_vgic_sync_to_cpu(struct kvm_vcpu *vcpu) {}
static inline void kvm_vgic_sync_from_cpu(struct kvm_vcpu *vcpu) {}

static inline int kvm_vgic_inject_irq(struct kvm *kvm, int cpuid,
				      const struct kvm_irq_level *irq)
{
	return 0;
}

static inline int kvm_vgic_vcpu_pending_irq(struct kvm_vcpu *vcpu)
{
	return 0;
}

static inline bool vgic_handle_mmio(struct kvm_vcpu *vcpu, struct kvm_run *run,
				    struct kvm_exit_mmio *mmio)
{
	return false;
}

static inline int irqchip_in_kernel(struct kvm *kvm)
{
	return 0;
}

static inline bool kvm_vgic_initialized(struct kvm *kvm)
{
	return true;
}

static inline int vgic_active_irq(struct kvm_vcpu *vcpu)
{
	return 0;
}
#endif

#endif
