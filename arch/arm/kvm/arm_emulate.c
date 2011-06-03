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

#include <linux/mm.h>
#include <asm/kvm_arm.h>
#include <asm/kvm_host.h>
#include <asm/kvm_emulate.h>

#include "trace.h"

struct coproc_params {
	unsigned long CRm;
	unsigned long CRn;
	unsigned long Op1;
	unsigned long Op2;
	unsigned long Rt1;
	unsigned long Rt2;
	bool is_64bit;
	bool is_write;
};

#define CP15_OP(_vcpu, _params, _cp15_reg) \
do { \
	if (_params->is_write) \
		_vcpu->arch.cp15._cp15_reg = vcpu_reg(_vcpu, _params->Rt1); \
	else \
		vcpu_reg(_vcpu, _params->Rt1) = _vcpu->arch.cp15._cp15_reg; \
} while (0);


/*
 * Return a pointer to the register number valid in the specified mode of
 * the virtual CPU.
 */
u32* kvm_vcpu_reg(struct kvm_vcpu *vcpu, u8 reg_num, u32 mode)
{
	struct kvm_vcpu_regs *regs;
	u8 reg_idx;
	BUG_ON(reg_num > 15);

	regs = &vcpu->arch.regs;

	/* The PC is trivial */
	if (reg_num == 15)
		return &(regs->pc);

	/* Non-banked registers */
	if (reg_num < 8)
		return &(regs->usr_regs[reg_num]);

	/* Banked registers r13 and r14 */
	if (reg_num >= 13) {
		reg_idx = reg_num - 13; /* 0=r13 and 1=r14 */
		switch (mode) {
		case MODE_FIQ:
			return &(regs->fiq_regs[reg_idx + 5]);
		case MODE_IRQ:
			return &(regs->irq_regs[reg_idx]);
		case MODE_SVC:
			return &(regs->svc_regs[reg_idx]);
		case MODE_ABT:
			return &(regs->abt_regs[reg_idx]);
		case MODE_UND:
			return &(regs->und_regs[reg_idx]);
		case MODE_USR:
		case MODE_SYS:
			return &(regs->usr_regs[reg_idx]);
		}
	}

	/* Banked FIQ registers r8-r12 */
	if (reg_num >= 8 && reg_num <= 12) {
		if (mode == MODE_FIQ) {
			reg_idx = reg_num - 8; /* 0=r8, ..., 4=r12 */
			return &(regs->fiq_regs[reg_idx]);
		} else
			return &(regs->usr_regs[reg_num]);
	}

	BUG();
	return NULL;
}

static inline void print_cp_instr(struct coproc_params *p)
{
	if (p->is_64bit) {
		kvm_msg("    %s\tp15, %u, r%u, r%u, c%u",
				(p->is_write) ? "mcrr" : "mrrc",
				p->Op1, p->Rt1, p->Rt2, p->CRm);
	} else {
		kvm_msg("    %s\tp15, %u, r%u, c%u, c%u, %u",
				(p->is_write) ? "mcr" : "mrc",
				p->Op1, p->Rt1, p->CRn, p->CRm, p->Op2);
	}
}

int kvm_handle_cp10_id(struct kvm_vcpu *vcpu, struct kvm_run *run)
{
	KVMARM_NOT_IMPLEMENTED();
	return -EINVAL;
}

int kvm_handle_cp_0_13_access(struct kvm_vcpu *vcpu, struct kvm_run *run)
{
	KVMARM_NOT_IMPLEMENTED();
	return -EINVAL;
}

int kvm_handle_cp14_load_store(struct kvm_vcpu *vcpu, struct kvm_run *run)
{
	KVMARM_NOT_IMPLEMENTED();
	return -EINVAL;
}

int kvm_handle_cp14_access(struct kvm_vcpu *vcpu, struct kvm_run *run)
{
	KVMARM_NOT_IMPLEMENTED();
	return -EINVAL;
}

/**
 * emulate_cp15_cp15_access -- emulates cp15 accesses for CRn == 10
 * @vcpu: The VCPU pointer
 * @p:    Thr coprocessor parameters struct pointer holding trap inst. details
 *
 * This funciton may not need to exist - if we can ignore guest attempts to
 * tamper with TLB lockdowns then it should be enough to store/restore the
 * host/guest PRRR and NMRR memory remap registers and allow guest direct access
 * to these registers.
 */
static int emulate_cp15_cp10_access(struct kvm_vcpu *vcpu,
				    struct coproc_params *p)
{
	BUG_ON(p->CRn != 10);
	BUG_ON(p->is_64bit);

	if ((p->CRm == 0 || p->CRm == 1 || p->CRm == 4 || p->CRm == 8) &&
	    (p->Op2 <= 7)) {
		/* TLB Lockdown operations - ignored */
		return 0;
	}

	if (p->CRm == 2 && p->Op2 == 0) {
		CP15_OP(vcpu, p, c10_PRRR);
		return 0;
	}

	if (p->CRm == 2 && p->Op2 == 1) {
		CP15_OP(vcpu, p, c10_NMRR);
		return 0;
	}

	return -EINVAL;
}

/**
 * kvm_handle_cp15_access -- handles a trap on a guest CP15 access
 * @vcpu: The VCPU pointer
 * @run:  The kvm_run struct
 *
 * Investigates the CRn/CRm and wether this was mcr/mrc or mcrr/mrrc and either
 * simply errors out if the operation was not supported (should maybe raise
 * undefined to guest instead?) and otherwise emulated access.
 */
int kvm_handle_cp15_access(struct kvm_vcpu *vcpu, struct kvm_run *run)
{
	unsigned long hsr_ec, instr_len;
	struct coproc_params params;
	int ret = 0;

	hsr_ec = vcpu->arch.hsr >> HSR_EC_SHIFT;
	params.CRm = (vcpu->arch.hsr >> 1) & 0xf;
	params.Rt1 = (vcpu->arch.hsr >> 5) & 0xf;
	BUG_ON(params.Rt1 >= 15);
	params.is_write = ((vcpu->arch.hsr & 1) == 0);
	params.is_64bit = (hsr_ec == HSR_EC_CP15_64);

	if (params.is_64bit) {
		/* mrrc, mccr operation */
		params.Op1 = (vcpu->arch.hsr >> 16) & 0xf;
		params.Op2 = 0;
		params.Rt2 = (vcpu->arch.hsr >> 10) & 0xf;
		BUG_ON(params.Rt2 >= 15);
		params.CRn = 0;
	} else {
		params.CRn = (vcpu->arch.hsr >> 10) & 0xf;
		params.Op1 = (vcpu->arch.hsr >> 14) & 0x7;
		params.Op2 = (vcpu->arch.hsr >> 17) & 0x7;
		params.Rt2 = 0;
	}

	/* So far no mrrc/mcrr accesses are emulated */
	if (params.is_64bit)
		goto unsupp_err_out;

	switch (params.CRn) {
	case 10:
		ret = emulate_cp15_cp10_access(vcpu, &params);
		break;
	default:
		ret = -EINVAL;
		break;
	}

	if (ret)
		goto unsupp_err_out;

	/* Skip instruction, since it was emulated */
	instr_len = ((vcpu->arch.hsr >> 25) & 1) ? 4 : 2;
	vcpu_reg(vcpu, 15) += instr_len;

	return ret;
unsupp_err_out:
	kvm_msg("Unsupported guest CP15 access:");
	print_cp_instr(&params);
	return -EINVAL;
}

int kvm_handle_wfi(struct kvm_vcpu *vcpu, struct kvm_run *run)
{
	KVMARM_NOT_IMPLEMENTED();
	return -EINVAL;
}
