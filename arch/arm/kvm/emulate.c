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
#include <trace/events/kvm.h>

#include "trace.h"

#define USR_REG_OFFSET(_reg) \
	offsetof(struct kvm_vcpu_arch, regs.usr_regs[_reg])

static const unsigned long vcpu_reg_offsets[MODE_SYS + 1][16] = {
	/* FIQ Registers */
	{
		USR_REG_OFFSET(0), USR_REG_OFFSET(1), USR_REG_OFFSET(2),
		USR_REG_OFFSET(3), USR_REG_OFFSET(4), USR_REG_OFFSET(5),
		USR_REG_OFFSET(6), USR_REG_OFFSET(7),
		offsetof(struct kvm_vcpu_arch, regs.fiq_regs[1]), /* r8 */
		offsetof(struct kvm_vcpu_arch, regs.fiq_regs[1]), /* r9 */
		offsetof(struct kvm_vcpu_arch, regs.fiq_regs[2]), /* r10 */
		offsetof(struct kvm_vcpu_arch, regs.fiq_regs[3]), /* r11 */
		offsetof(struct kvm_vcpu_arch, regs.fiq_regs[4]), /* r12 */
		offsetof(struct kvm_vcpu_arch, regs.fiq_regs[5]), /* r13 */
		offsetof(struct kvm_vcpu_arch, regs.fiq_regs[6]), /* r14 */
		offsetof(struct kvm_vcpu_arch, regs.pc)		  /* r15 */
	},

	/* IRQ Registers */
	{
		USR_REG_OFFSET(0), USR_REG_OFFSET(1), USR_REG_OFFSET(2),
		USR_REG_OFFSET(3), USR_REG_OFFSET(4), USR_REG_OFFSET(5),
		USR_REG_OFFSET(6), USR_REG_OFFSET(7), USR_REG_OFFSET(8),
		USR_REG_OFFSET(9), USR_REG_OFFSET(10), USR_REG_OFFSET(11),
		USR_REG_OFFSET(12),
		offsetof(struct kvm_vcpu_arch, regs.irq_regs[0]), /* r13 */
		offsetof(struct kvm_vcpu_arch, regs.irq_regs[1]), /* r14 */
		offsetof(struct kvm_vcpu_arch, regs.pc)	          /* r15 */
	},

	/* SVC Registers */
	{
		USR_REG_OFFSET(0), USR_REG_OFFSET(1), USR_REG_OFFSET(2),
		USR_REG_OFFSET(3), USR_REG_OFFSET(4), USR_REG_OFFSET(5),
		USR_REG_OFFSET(6), USR_REG_OFFSET(7), USR_REG_OFFSET(8),
		USR_REG_OFFSET(9), USR_REG_OFFSET(10), USR_REG_OFFSET(11),
		USR_REG_OFFSET(12),
		offsetof(struct kvm_vcpu_arch, regs.svc_regs[0]), /* r13 */
		offsetof(struct kvm_vcpu_arch, regs.svc_regs[1]), /* r14 */
		offsetof(struct kvm_vcpu_arch, regs.pc)		  /* r15 */
	},

	/* ABT Registers */
	{
		USR_REG_OFFSET(0), USR_REG_OFFSET(1), USR_REG_OFFSET(2),
		USR_REG_OFFSET(3), USR_REG_OFFSET(4), USR_REG_OFFSET(5),
		USR_REG_OFFSET(6), USR_REG_OFFSET(7), USR_REG_OFFSET(8),
		USR_REG_OFFSET(9), USR_REG_OFFSET(10), USR_REG_OFFSET(11),
		USR_REG_OFFSET(12),
		offsetof(struct kvm_vcpu_arch, regs.abt_regs[0]), /* r13 */
		offsetof(struct kvm_vcpu_arch, regs.abt_regs[1]), /* r14 */
		offsetof(struct kvm_vcpu_arch, regs.pc)	          /* r15 */
	},

	/* UND Registers */
	{
		USR_REG_OFFSET(0), USR_REG_OFFSET(1), USR_REG_OFFSET(2),
		USR_REG_OFFSET(3), USR_REG_OFFSET(4), USR_REG_OFFSET(5),
		USR_REG_OFFSET(6), USR_REG_OFFSET(7), USR_REG_OFFSET(8),
		USR_REG_OFFSET(9), USR_REG_OFFSET(10), USR_REG_OFFSET(11),
		USR_REG_OFFSET(12),
		offsetof(struct kvm_vcpu_arch, regs.und_regs[0]), /* r13 */
		offsetof(struct kvm_vcpu_arch, regs.und_regs[1]), /* r14 */
		offsetof(struct kvm_vcpu_arch, regs.pc)	          /* r15 */
	},

	/* USR Registers */
	{
		USR_REG_OFFSET(0), USR_REG_OFFSET(1), USR_REG_OFFSET(2),
		USR_REG_OFFSET(3), USR_REG_OFFSET(4), USR_REG_OFFSET(5),
		USR_REG_OFFSET(6), USR_REG_OFFSET(7), USR_REG_OFFSET(8),
		USR_REG_OFFSET(9), USR_REG_OFFSET(10), USR_REG_OFFSET(11),
		USR_REG_OFFSET(12),
		offsetof(struct kvm_vcpu_arch, regs.usr_regs[13]), /* r13 */
		offsetof(struct kvm_vcpu_arch, regs.usr_regs[14]), /* r14 */
		offsetof(struct kvm_vcpu_arch, regs.pc)	           /* r15 */
	},

	/* SYS Registers */
	{
		USR_REG_OFFSET(0), USR_REG_OFFSET(1), USR_REG_OFFSET(2),
		USR_REG_OFFSET(3), USR_REG_OFFSET(4), USR_REG_OFFSET(5),
		USR_REG_OFFSET(6), USR_REG_OFFSET(7), USR_REG_OFFSET(8),
		USR_REG_OFFSET(9), USR_REG_OFFSET(10), USR_REG_OFFSET(11),
		USR_REG_OFFSET(12),
		offsetof(struct kvm_vcpu_arch, regs.usr_regs[13]), /* r13 */
		offsetof(struct kvm_vcpu_arch, regs.usr_regs[14]), /* r14 */
		offsetof(struct kvm_vcpu_arch, regs.pc)	           /* r15 */
	},
};

/*
 * Return a pointer to the register number valid in the specified mode of
 * the virtual CPU.
 */
u32 *kvm_vcpu_reg(struct kvm_vcpu *vcpu, u8 reg_num, u32 mode)
{
	BUG_ON(reg_num > 15);
	BUG_ON(mode > MODE_SYS);

	return (u32 *)((void *)&vcpu->arch + vcpu_reg_offsets[mode][reg_num]);
}

/******************************************************************************
 * Co-processor emulation
 */

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

static void cp15_op(struct kvm_vcpu *vcpu, struct coproc_params *p,
			   enum cp15_regs cp15_reg)
{
	if (p->is_write)
		vcpu->arch.cp15[cp15_reg] = *vcpu_reg(vcpu, p->Rt1);
	else
		*vcpu_reg(vcpu, p->Rt1) = vcpu->arch.cp15[cp15_reg];
}

static void print_cp_instr(struct coproc_params *p)
{
	if (p->is_64bit) {
		kvm_debug("%s\tp15, %lu, r%lu, r%lu, c%lu",
			  (p->is_write) ? "mcrr" : "mrrc",
			  p->Op1, p->Rt1, p->Rt2, p->CRm);
	} else {
		kvm_debug("%s\tp15, %lu, r%lu, c%lu, c%lu, %lu",
			  (p->is_write) ? "mcr" : "mrc",
			  p->Op1, p->Rt1, p->CRn, p->CRm, p->Op2);
	}
}

int kvm_handle_cp10_id(struct kvm_vcpu *vcpu, struct kvm_run *run)
{
	return -EINVAL;
}

int kvm_handle_cp_0_13_access(struct kvm_vcpu *vcpu, struct kvm_run *run)
{
	return -EINVAL;
}

int kvm_handle_cp14_load_store(struct kvm_vcpu *vcpu, struct kvm_run *run)
{
	return -EINVAL;
}

int kvm_handle_cp14_access(struct kvm_vcpu *vcpu, struct kvm_run *run)
{
	return -EINVAL;
}

/**
 * emulate_cp15_c10_access -- emulates cp15 accesses for CRn == 10
 * @vcpu: The VCPU pointer
 * @p:    The coprocessor parameters struct pointer holding trap inst. details
 *
 * This function may not need to exist - if we can ignore guest attempts to
 * tamper with TLB lockdowns then it should be enough to store/restore the
 * host/guest PRRR and NMRR memory remap registers and allow guest direct access
 * to these registers.
 */
static int emulate_cp15_c10_access(struct kvm_vcpu *vcpu,
				   struct coproc_params *p)
{
	BUG_ON(p->CRn != 10);
	BUG_ON(p->is_64bit);

	if ((p->CRm == 0 || p->CRm == 1 || p->CRm == 4 || p->CRm == 8) &&
	    (p->Op2 <= 7)) {
		/* TLB Lockdown operations - ignored */
		return 0;
	}

	/*
	 * The role of these registers depends on whether LPAE is defined or
	 * not, but there shouldn't be any breakage in any case - we may
	 * simply not respect the nomenclature here.
	 */

	if (p->CRm == 2 && p->Op1 == 0 && p->Op2 == 0) {
		cp15_op(vcpu, p, c10_PRRR);
		return 0;
	}

	if (p->CRm == 2 && p->Op1 == 0 && p->Op2 == 1) {
		cp15_op(vcpu, p, c10_NMRR);
		return 0;
	}

	return -EINVAL;
}

/**
 * emulate_cp15_c15_access -- emulates cp15 accesses for CRn == 15
 * @vcpu: The VCPU pointer
 * @p:    The coprocessor parameters struct pointer holding trap inst. details
 *
 * The CP15 c15 register is architecturally implementation defined, but some
 * guest kernels attempt to read/write a diagnostics register here. We always
 * return 0 and ignore writes and hope for the best.
 *
 * This may need to be refined.
 */
static int emulate_cp15_c15_access(struct kvm_vcpu *vcpu,
				   struct coproc_params *p)
{
	trace_kvm_emulate_cp15_imp(p->Op1, p->Rt1, p->CRn, p->CRm,
				   p->Op2, p->is_write);

	if (!p->is_write)
		*vcpu_reg(vcpu, p->Rt1) = 0;

	return 0;
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
		ret = emulate_cp15_c10_access(vcpu, &params);
		break;
	case 15:
		ret = emulate_cp15_c15_access(vcpu, &params);
		break;
	default:
		ret = -EINVAL;
		break;
	}

	if (ret)
		goto unsupp_err_out;

	/* Skip instruction, since it was emulated */
	instr_len = ((vcpu->arch.hsr >> 25) & 1) ? 4 : 2;
	*vcpu_reg(vcpu, 15) += instr_len;

	return ret;
unsupp_err_out:
	kvm_err("Unsupported guest CP15 access at: %08x\n", vcpu->arch.regs.pc);
	print_cp_instr(&params);
	return -EINVAL;
}

int kvm_handle_wfi(struct kvm_vcpu *vcpu, struct kvm_run *run)
{
	return 0;
}
