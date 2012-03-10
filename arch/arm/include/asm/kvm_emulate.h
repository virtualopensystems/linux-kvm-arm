/*
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
 *
 */

#ifndef __ARM_KVM_EMULATE_H__
#define __ARM_KVM_EMULATE_H__

#include <linux/kvm_host.h>
#include <asm/kvm_asm.h>

u32 *kvm_vcpu_reg(struct kvm_vcpu *vcpu, u8 reg_num, u32 mode);

static inline unsigned char vcpu_mode(struct kvm_vcpu *vcpu)
{
	u8 modes_table[16] = {
		MODE_USR,	/* 0x0 */
		MODE_FIQ,	/* 0x1 */
		MODE_IRQ,	/* 0x2 */
		MODE_SVC,	/* 0x3 */
		0xf, 0xf, 0xf,
		MODE_ABT,	/* 0x7 */
		0xf, 0xf, 0xf,
		MODE_UND,	/* 0xb */
		0xf, 0xf, 0xf,
		MODE_SYS};	/* 0xf */

	BUG_ON(modes_table[vcpu->arch.regs.cpsr & 0xf] == 0xf);
	return modes_table[vcpu->arch.regs.cpsr & 0xf];
}

int kvm_handle_cp10_id(struct kvm_vcpu *vcpu, struct kvm_run *run);
int kvm_handle_cp_0_13_access(struct kvm_vcpu *vcpu, struct kvm_run *run);
int kvm_handle_cp14_load_store(struct kvm_vcpu *vcpu, struct kvm_run *run);
int kvm_handle_cp14_access(struct kvm_vcpu *vcpu, struct kvm_run *run);
int kvm_handle_cp15_32(struct kvm_vcpu *vcpu, struct kvm_run *run);
int kvm_handle_cp15_64(struct kvm_vcpu *vcpu, struct kvm_run *run);
int kvm_handle_wfi(struct kvm_vcpu *vcpu, struct kvm_run *run);
int kvm_emulate_mmio_ls(struct kvm_vcpu *vcpu, phys_addr_t fault_ipa,
			unsigned long instr);

/*
 * Return the SPSR for the specified mode of the virtual CPU.
 */
static inline u32 *kvm_vcpu_spsr(struct kvm_vcpu *vcpu, u32 mode)
{
	switch (mode) {
	case MODE_SVC:
		return &vcpu->arch.regs.svc_regs[2];
	case MODE_ABT:
		return &vcpu->arch.regs.svc_regs[2];
	case MODE_UND:
		return &vcpu->arch.regs.svc_regs[2];
	case MODE_IRQ:
		return &vcpu->arch.regs.svc_regs[2];
	case MODE_FIQ:
		return &vcpu->arch.regs.fiq_regs[7];
	default:
		BUG();
	}
}

/* Get vcpu register for current mode */
static inline u32 *vcpu_reg(struct kvm_vcpu *vcpu, unsigned long reg_num)
{
	return kvm_vcpu_reg(vcpu, reg_num, vcpu_mode(vcpu));
}

static inline u32 *vcpu_cpsr(struct kvm_vcpu *vcpu)
{
	return &vcpu->arch.regs.cpsr;
}

/* Get vcpu SPSR for current mode */
static inline u32 *vcpu_spsr(struct kvm_vcpu *vcpu)
{
	return kvm_vcpu_spsr(vcpu, vcpu_mode(vcpu));
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
