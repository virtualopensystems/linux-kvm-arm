/*
 * Copyright (C) 2012 - Virtual Open Systems and Columbia University
 * Author: Christoffer Dall <c.dall@virtualopensystems.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 2, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#ifndef __ARM_KVM_EMULATE_H__
#define __ARM_KVM_EMULATE_H__

#include <linux/kvm_host.h>
#include <asm/kvm_asm.h>

u32 *vcpu_reg_mode(struct kvm_vcpu *vcpu, u8 reg_num, u32 cpsr);
u32 *vcpu_spsr_mode(struct kvm_vcpu *vcpu, u32 cpsr);

/* Get vcpu register for current mode */
static inline u32 *vcpu_reg(struct kvm_vcpu *vcpu, unsigned long reg_num)
{
	return vcpu_reg_mode(vcpu, reg_num, vcpu->arch.regs.cpsr);
}

static inline u32 *vcpu_pc(struct kvm_vcpu *vcpu)
{
	return vcpu_reg(vcpu, 15);
}

static inline u32 *vcpu_cpsr(struct kvm_vcpu *vcpu)
{
	return &vcpu->arch.regs.cpsr;
}

/* Get vcpu SPSR for current mode */
static inline u32 *vcpu_spsr(struct kvm_vcpu *vcpu)
{
	return vcpu_spsr_mode(vcpu, vcpu->arch.regs.cpsr);
}

static inline bool mode_has_spsr(struct kvm_vcpu *vcpu)
{
	unsigned long cpsr_mode = vcpu->arch.regs.cpsr & MODE_MASK;
	return (cpsr_mode > USR_MODE && cpsr_mode < SYSTEM_MODE);
}

static inline bool vcpu_mode_priv(struct kvm_vcpu *vcpu)
{
	unsigned long cpsr_mode = vcpu->arch.regs.cpsr & MODE_MASK;
	return cpsr_mode > USR_MODE;;
}

#endif /* __ARM_KVM_EMULATE_H__ */
