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

#define REG_OFFSET(_reg) \
	(offsetof(struct kvm_vcpu_regs, _reg) / sizeof(u32))

#define USR_REG_OFFSET(_num) REG_OFFSET(usr_regs[_num])

static const unsigned long vcpu_reg_offsets[MODE_SYS + 1][16] = {
	/* FIQ Registers */
	{
		USR_REG_OFFSET(0), USR_REG_OFFSET(1), USR_REG_OFFSET(2),
		USR_REG_OFFSET(3), USR_REG_OFFSET(4), USR_REG_OFFSET(5),
		USR_REG_OFFSET(6), USR_REG_OFFSET(7),
		REG_OFFSET(fiq_regs[1]), /* r8 */
		REG_OFFSET(fiq_regs[1]), /* r9 */
		REG_OFFSET(fiq_regs[2]), /* r10 */
		REG_OFFSET(fiq_regs[3]), /* r11 */
		REG_OFFSET(fiq_regs[4]), /* r12 */
		REG_OFFSET(fiq_regs[5]), /* r13 */
		REG_OFFSET(fiq_regs[6]), /* r14 */
		REG_OFFSET(pc)		 /* r15 */
	},

	/* IRQ Registers */
	{
		USR_REG_OFFSET(0), USR_REG_OFFSET(1), USR_REG_OFFSET(2),
		USR_REG_OFFSET(3), USR_REG_OFFSET(4), USR_REG_OFFSET(5),
		USR_REG_OFFSET(6), USR_REG_OFFSET(7), USR_REG_OFFSET(8),
		USR_REG_OFFSET(9), USR_REG_OFFSET(10), USR_REG_OFFSET(11),
		USR_REG_OFFSET(12),
		REG_OFFSET(irq_regs[0]), /* r13 */
		REG_OFFSET(irq_regs[1]), /* r14 */
		REG_OFFSET(pc)	         /* r15 */
	},

	/* SVC Registers */
	{
		USR_REG_OFFSET(0), USR_REG_OFFSET(1), USR_REG_OFFSET(2),
		USR_REG_OFFSET(3), USR_REG_OFFSET(4), USR_REG_OFFSET(5),
		USR_REG_OFFSET(6), USR_REG_OFFSET(7), USR_REG_OFFSET(8),
		USR_REG_OFFSET(9), USR_REG_OFFSET(10), USR_REG_OFFSET(11),
		USR_REG_OFFSET(12),
		REG_OFFSET(svc_regs[0]), /* r13 */
		REG_OFFSET(svc_regs[1]), /* r14 */
		REG_OFFSET(pc)		 /* r15 */
	},

	/* ABT Registers */
	{
		USR_REG_OFFSET(0), USR_REG_OFFSET(1), USR_REG_OFFSET(2),
		USR_REG_OFFSET(3), USR_REG_OFFSET(4), USR_REG_OFFSET(5),
		USR_REG_OFFSET(6), USR_REG_OFFSET(7), USR_REG_OFFSET(8),
		USR_REG_OFFSET(9), USR_REG_OFFSET(10), USR_REG_OFFSET(11),
		USR_REG_OFFSET(12),
		REG_OFFSET(abt_regs[0]), /* r13 */
		REG_OFFSET(abt_regs[1]), /* r14 */
		REG_OFFSET(pc)	         /* r15 */
	},

	/* UND Registers */
	{
		USR_REG_OFFSET(0), USR_REG_OFFSET(1), USR_REG_OFFSET(2),
		USR_REG_OFFSET(3), USR_REG_OFFSET(4), USR_REG_OFFSET(5),
		USR_REG_OFFSET(6), USR_REG_OFFSET(7), USR_REG_OFFSET(8),
		USR_REG_OFFSET(9), USR_REG_OFFSET(10), USR_REG_OFFSET(11),
		USR_REG_OFFSET(12),
		REG_OFFSET(und_regs[0]), /* r13 */
		REG_OFFSET(und_regs[1]), /* r14 */
		REG_OFFSET(pc)	         /* r15 */
	},

	/* USR Registers */
	{
		USR_REG_OFFSET(0), USR_REG_OFFSET(1), USR_REG_OFFSET(2),
		USR_REG_OFFSET(3), USR_REG_OFFSET(4), USR_REG_OFFSET(5),
		USR_REG_OFFSET(6), USR_REG_OFFSET(7), USR_REG_OFFSET(8),
		USR_REG_OFFSET(9), USR_REG_OFFSET(10), USR_REG_OFFSET(11),
		USR_REG_OFFSET(12),
		REG_OFFSET(usr_regs[13]), /* r13 */
		REG_OFFSET(usr_regs[14]), /* r14 */
		REG_OFFSET(pc)	          /* r15 */
	},

	/* SYS Registers */
	{
		USR_REG_OFFSET(0), USR_REG_OFFSET(1), USR_REG_OFFSET(2),
		USR_REG_OFFSET(3), USR_REG_OFFSET(4), USR_REG_OFFSET(5),
		USR_REG_OFFSET(6), USR_REG_OFFSET(7), USR_REG_OFFSET(8),
		USR_REG_OFFSET(9), USR_REG_OFFSET(10), USR_REG_OFFSET(11),
		USR_REG_OFFSET(12),
		REG_OFFSET(usr_regs[13]), /* r13 */
		REG_OFFSET(usr_regs[14]), /* r14 */
		REG_OFFSET(pc)	          /* r15 */
	},
};

/*
 * Return a pointer to the register number valid in the specified mode of
 * the virtual CPU.
 */
u32 *vcpu_reg_mode(struct kvm_vcpu *vcpu, u8 reg_num, u32 mode)
{
	u32 *reg_array = (u32 *)&vcpu->arch.regs;

	BUG_ON(reg_num > 15);
	BUG_ON(mode > MODE_SYS);

	return reg_array + vcpu_reg_offsets[mode][reg_num];
}

/******************************************************************************
 * Co-processor emulation
 */

struct coproc_params {
	unsigned long CRn;
	unsigned long CRm;
	unsigned long Op1;
	unsigned long Op2;
	unsigned long Rt1;
	unsigned long Rt2;
	bool is_64bit;
	bool is_write;
};

static void print_cp_instr(const struct coproc_params *p)
{
	/* Look, we even formatted it for you to paste into the table! */
	if (p->is_64bit) {
		kvm_err("{ CRn(DF), CRm(%2lu), Op1(%2lu), Op2(DF), is64, %-6s"
			" func, arg},\n",
			p->CRm, p->Op1, p->is_write ? "WRITE," : "READ,");
	} else {
		kvm_err("{ CRn(%2lu), CRm(%2lu), Op1(%2lu), Op2(%2lu), is32,"
			" %-6s func, arg},\n",
			p->CRn, p->CRm, p->Op1, p->Op2,
			p->is_write ? "WRITE," : "READ,");
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

static bool ignore_write(struct kvm_vcpu *vcpu,
			 const struct coproc_params *p,
			 unsigned long arg)
{
	if (arg)
		trace_kvm_emulate_cp15_imp(p->Op1, p->Rt1, p->CRn, p->CRm,
					   p->Op2, p->is_write);
	return true;
}

static bool read_zero(struct kvm_vcpu *vcpu,
		      const struct coproc_params *p,
		      unsigned long arg)
{
	if (arg)
		trace_kvm_emulate_cp15_imp(p->Op1, p->Rt1, p->CRn, p->CRm,
					   p->Op2, p->is_write);
	*vcpu_reg(vcpu, p->Rt1) = 0;
	return true;
}

static bool read_l2ctlr(struct kvm_vcpu *vcpu,
			const struct coproc_params *p,
			unsigned long arg)
{
	u32 l2ctlr, ncores;

	asm volatile("mrc p15, 1, %0, c9, c0, 2\n" : "=r" (l2ctlr));
	l2ctlr &= ~(3 << 24);
	ncores = atomic_read(&vcpu->kvm->online_vcpus) - 1;
	l2ctlr |= (ncores & 3) << 24;
	*vcpu_reg(vcpu, p->Rt1) = l2ctlr;

	return true;
}

static bool access_cp15_reg(struct kvm_vcpu *vcpu,
			    const struct coproc_params *p,
			    unsigned long cp15_reg)
{
	if (p->is_write)
		vcpu->arch.cp15[cp15_reg] = *vcpu_reg(vcpu, p->Rt1);
	else
		*vcpu_reg(vcpu, p->Rt1) = vcpu->arch.cp15[cp15_reg];
	return true;
}

/* Any field which is 0xFFFFFFFF == DF */
struct coproc_emulate {
	unsigned long CRn;
	unsigned long CRm;
	unsigned long Op1;
	unsigned long Op2;

	unsigned long is_64;
	unsigned long is_w;

	bool (*f)(struct kvm_vcpu *,
		  const struct coproc_params *,
		  unsigned long);
	unsigned long arg;
};

#define DF (-1UL) /* Default: If nothing else fits, use this one */
#define CRn(_x)		.CRn = _x
#define CRm(_x) 	.CRm = _x
#define Op1(_x) 	.Op1 = _x
#define Op2(_x) 	.Op2 = _x
#define is64		.is_64 = true
#define is32		.is_64 = false
#define READ		.is_w  = false
#define WRITE		.is_w  = true
#define RW		.is_w  = DF

static const struct coproc_emulate coproc_emulate[] = {
	/*
	 * L2CTLR access:
	 *
	 * Ignore writes completely.
	 *
	 * FIXME: Hack Alert: Read zero as default case.
	 */
	{ CRn( 9), CRm( 0), Op1( 1), Op2( 2), is32,  WRITE, ignore_write},
	{ CRn( 9), CRm( 0), Op1( 1), Op2( 2), is32,  READ,  read_l2ctlr},
	{ CRn( 9), CRm(DF), Op1(DF), Op2(DF), is32,  WRITE, ignore_write},
	{ CRn( 9), CRm(DF), Op1(DF), Op2(DF), is32,  READ,  read_zero},

	/*
	 * These CRn == 10 entries may not need to exist - if we can
	 * ignore guest attempts to tamper with TLB lockdowns then it
	 * should be enough to store/restore the host/guest PRRR and
	 * NMRR memory remap registers and allow guest direct access
	 * to these registers.
	 *
	 * TLB Lockdown operations - ignored
	 */
	{ CRn(10), CRm( 0), Op1(DF), Op2(DF), is32,  WRITE, ignore_write},
	{ CRn(10), CRm( 2), Op1( 0), Op2( 0), is32,  RW,    access_cp15_reg,
							    c10_PRRR},
	{ CRn(10), CRm( 2), Op1( 0), Op2( 1), is32,  RW,    access_cp15_reg,
							    c10_NMRR},

	/*
	 * The CP15 c15 register is architecturally implementation
	 * defined, but some guest kernels attempt to read/write a
	 * diagnostics register here. We always return 0 and ignore
	 * writes and hope for the best.
	 */
	{ CRn(15), CRm(DF), Op1(DF), Op2(DF), is32,  WRITE, ignore_write, 1},
	{ CRn(15), CRm(DF), Op1(DF), Op2(DF), is32,  READ,  read_zero,    1},
};

#undef is64
#undef is32
#undef READ
#undef WRITE
#undef RW

static inline bool match(unsigned long val, unsigned long param)
{
	return param == DF || val == param;
}

static int emulate_cp15(struct kvm_vcpu *vcpu,
			const struct coproc_params *params)
{
	unsigned long instr_len, i;

	for (i = 0; i < ARRAY_SIZE(coproc_emulate); i++) {
		const struct coproc_emulate *e = &coproc_emulate[i];

		if (!match(params->is_64bit, e->is_64))
			continue;
		if (!match(params->is_write, e->is_w))
			continue;
		if (!match(params->CRn, e->CRn))
			continue;
		if (!match(params->CRm, e->CRm))
			continue;
		if (!match(params->Op1, e->Op1))
			continue;
		if (!match(params->Op2, e->Op2))
			continue;

		/* If function fails, it should complain. */
		if (!e->f(vcpu, params, e->arg))
			goto fail;

		/* Skip instruction, since it was emulated */
		instr_len = ((vcpu->arch.hsr >> 25) & 1) ? 4 : 2;
		*vcpu_reg(vcpu, 15) += instr_len;
		return 0;
	}

	kvm_err("Unsupported guest CP15 access at: %08x\n",
		vcpu->arch.regs.pc);
	print_cp_instr(params);
fail:
	return -EINVAL;
}

/**
 * kvm_handle_cp15_64 -- handles a mrrc/mcrr trap on a guest CP15 access
 * @vcpu: The VCPU pointer
 * @run:  The kvm_run struct
 */
int kvm_handle_cp15_64(struct kvm_vcpu *vcpu, struct kvm_run *run)
{
	struct coproc_params params;

	params.CRm = (vcpu->arch.hsr >> 1) & 0xf;
	params.Rt1 = (vcpu->arch.hsr >> 5) & 0xf;
	params.is_write = ((vcpu->arch.hsr & 1) == 0);
	params.is_64bit = true;

	params.Op1 = (vcpu->arch.hsr >> 16) & 0xf;
	params.Op2 = 0;
	params.Rt2 = (vcpu->arch.hsr >> 10) & 0xf;
	params.CRn = 0;

	return emulate_cp15(vcpu, &params);
}

/**
 * kvm_handle_cp15_32 -- handles a mrc/mcr trap on a guest CP15 access
 * @vcpu: The VCPU pointer
 * @run:  The kvm_run struct
 */
int kvm_handle_cp15_32(struct kvm_vcpu *vcpu, struct kvm_run *run)
{
	struct coproc_params params;

	params.CRm = (vcpu->arch.hsr >> 1) & 0xf;
	params.Rt1 = (vcpu->arch.hsr >> 5) & 0xf;
	params.is_write = ((vcpu->arch.hsr & 1) == 0);
	params.is_64bit = false;

	params.CRn = (vcpu->arch.hsr >> 10) & 0xf;
	params.Op1 = (vcpu->arch.hsr >> 14) & 0x7;
	params.Op2 = (vcpu->arch.hsr >> 17) & 0x7;
	params.Rt2 = 0;

	return emulate_cp15(vcpu, &params);
}

int kvm_handle_wfi(struct kvm_vcpu *vcpu, struct kvm_run *run)
{
	return 0;
}
