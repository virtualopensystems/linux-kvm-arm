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

/*
 * The in-kernel MMIO emulation code wants to use a copy of run->mmio,
 * which is an anonymous type. Use our own type instead.
 */
struct kvm_exit_mmio {
	phys_addr_t	phys_addr;
	u8		data[8];
	u32		len;
	bool		is_write;
};

static inline void kvm_prepare_mmio(struct kvm_run *run,
				    struct kvm_exit_mmio *mmio)
{
	run->mmio.phys_addr	= mmio->phys_addr;
	run->mmio.len		= mmio->len;
	run->mmio.is_write	= mmio->is_write;
	memcpy(run->mmio.data, mmio->data, mmio->len);
	run->exit_reason	= KVM_EXIT_MMIO;
}

u32 *vcpu_reg_mode(struct kvm_vcpu *vcpu, u8 reg_num, enum vcpu_mode mode);

static inline u8 __vcpu_mode(u32 cpsr)
{
	u8 modes_table[32] = {
		0xf, 0xf, 0xf, 0xf, 0xf, 0xf, 0xf, 0xf,
		0xf, 0xf, 0xf, 0xf, 0xf, 0xf, 0xf, 0xf,
		MODE_USR,	/* 0x0 */
		MODE_FIQ,	/* 0x1 */
		MODE_IRQ,	/* 0x2 */
		MODE_SVC,	/* 0x3 */
		0xf, 0xf, 0xf,
		MODE_ABT,	/* 0x7 */
		0xf, 0xf, 0xf,
		MODE_UND,	/* 0xb */
		0xf, 0xf, 0xf,
		MODE_SYS	/* 0xf */
	};

	return modes_table[cpsr & 0x1f];
}

static inline enum vcpu_mode vcpu_mode(struct kvm_vcpu *vcpu)
{
	u8 mode = __vcpu_mode(vcpu->arch.regs.cpsr);
	BUG_ON(mode == 0xf);
	return mode;
}

int kvm_handle_wfi(struct kvm_vcpu *vcpu, struct kvm_run *run);
int kvm_emulate_mmio_ls(struct kvm_vcpu *vcpu, phys_addr_t fault_ipa,
			unsigned long instr, struct kvm_exit_mmio *mmio);
void kvm_skip_instr(struct kvm_vcpu *vcpu, bool is_wide_instr);
void kvm_inject_undefined(struct kvm_vcpu *vcpu);
void kvm_inject_dabt(struct kvm_vcpu *vcpu, unsigned long addr);
void kvm_inject_pabt(struct kvm_vcpu *vcpu, unsigned long addr);

/*
 * Return the SPSR for the specified mode of the virtual CPU.
 */
static inline u32 *vcpu_spsr_mode(struct kvm_vcpu *vcpu, enum vcpu_mode mode)
{
	switch (mode) {
	case MODE_SVC:
		return &vcpu->arch.regs.svc_regs[2];
	case MODE_ABT:
		return &vcpu->arch.regs.abt_regs[2];
	case MODE_UND:
		return &vcpu->arch.regs.und_regs[2];
	case MODE_IRQ:
		return &vcpu->arch.regs.irq_regs[2];
	case MODE_FIQ:
		return &vcpu->arch.regs.fiq_regs[7];
	default:
		BUG();
	}
}

/* Get vcpu register for current mode */
static inline u32 *vcpu_reg(struct kvm_vcpu *vcpu, unsigned long reg_num)
{
	return vcpu_reg_mode(vcpu, reg_num, vcpu_mode(vcpu));
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
	return vcpu_spsr_mode(vcpu, vcpu_mode(vcpu));
}

static inline bool mode_has_spsr(struct kvm_vcpu *vcpu)
{
	return (vcpu_mode(vcpu) < MODE_USR);
}

static inline bool vcpu_mode_priv(struct kvm_vcpu *vcpu)
{
	BUG_ON(vcpu_mode(vcpu) > MODE_SYS);
	return vcpu_mode(vcpu) != MODE_USR;
}

#endif /* __ARM_KVM_EMULATE_H__ */
