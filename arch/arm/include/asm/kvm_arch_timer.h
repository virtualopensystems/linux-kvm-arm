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

#ifndef __ASM_ARM_KVM_ARCH_TIMER_H
#define __ASM_ARM_KVM_ARCH_TIMER_H

#include <linux/clocksource.h>
#include <linux/hrtimer.h>
#include <linux/workqueue.h>

struct arch_timer_kvm {
#ifdef CONFIG_KVM_ARM_TIMER
	/* Is the timer enabled */
	bool			enabled;

	/*
	 * Virtual offset (kernel access it through cntvoff, HYP code
	 * access it as two 32bit values).
	 */
	union {
		cycle_t		cntvoff;
		struct {
			u32	low; 	/* Restored only */
			u32	high;  	/* Restored only */
		} cntvoff32;
	};
#endif
};

struct arch_timer_cpu {
#ifdef CONFIG_KVM_ARM_TIMER
	/* Background timer used when the guest is not running */
	struct hrtimer			timer;

	/* Work queued with the above timer expires */
	struct work_struct		expired;

	/* Background timer active */
	bool				armed;

	/* Timer IRQ */
	const struct kvm_irq_level	*irq;

	/* Registers: control register, timer value */
	u32				cntv_ctl;	/* Saved/restored */
	union {
		cycle_t			cntv_cval;
		struct {
			u32		low;		/* Saved/restored */
			u32		high;		/* Saved/restored */
		} cntv_cval32;
	};
#endif
};

#ifdef CONFIG_KVM_ARM_TIMER
int kvm_timer_hyp_init(void);
int kvm_timer_init(struct kvm *kvm);
void kvm_timer_vcpu_init(struct kvm_vcpu *vcpu);
void kvm_timer_sync_to_cpu(struct kvm_vcpu *vcpu);
void kvm_timer_sync_from_cpu(struct kvm_vcpu *vcpu);
void kvm_timer_vcpu_terminate(struct kvm_vcpu *vcpu);
#else
static inline int kvm_timer_hyp_init(void)
{
	return 0;
};

static inline int kvm_timer_init(struct kvm *kvm)
{
	return 0;
}

static inline void kvm_timer_vcpu_init(struct kvm_vcpu *vcpu) {}
static inline void kvm_timer_sync_to_cpu(struct kvm_vcpu *vcpu) {}
static inline void kvm_timer_sync_from_cpu(struct kvm_vcpu *vcpu) {}
static inline void kvm_timer_vcpu_terminate(struct kvm_vcpu *vcpu) {}
#endif

#endif
