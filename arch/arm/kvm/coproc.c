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
#include <linux/mm.h>
#include <linux/kvm_host.h>
#include <linux/uaccess.h>
#include <asm/kvm_arm.h>
#include <asm/kvm_host.h>
#include <asm/kvm_emulate.h>
#include <asm/kvm_coproc.h>
#include <asm/cacheflush.h>
#include <asm/cputype.h>
#include <trace/events/kvm.h>

#include "trace.h"

/******************************************************************************
 * Co-processor emulation
 *****************************************************************************/

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

struct coproc_reg {
	/* MRC/MCR/MRRC/MCRR instruction which accesses it. */
	unsigned long CRn;
	unsigned long CRm;
	unsigned long Op1;
	unsigned long Op2;

	bool is_64;

	/* Trapped access from guest, if non-NULL. */
	bool (*access)(struct kvm_vcpu *,
		       const struct coproc_params *,
		       const struct coproc_reg *);

	/* Initialization for vcpu. */
	void (*reset)(struct kvm_vcpu *, const struct coproc_reg *);

	/* Index into vcpu->arch.cp15[], or 0 if we don't need to save it. */
	enum cp15_regs reg;

	/* Value (usually reset value) */
	u64 val;
};

static void print_cp_instr(const struct coproc_params *p)
{
	/* Look, we even formatted it for you to paste into the table! */
	if (p->is_64bit) {
		kvm_pr_unimpl(" { CRm(%2lu), Op1(%2lu), is64, func_%s },\n",
			      p->CRm, p->Op1, p->is_write ? "write" : "read");
	} else {
		kvm_pr_unimpl(" { CRn(%2lu), CRm(%2lu), Op1(%2lu), Op2(%2lu), is32,"
			      " func_%s },\n",
			      p->CRn, p->CRm, p->Op1, p->Op2,
			      p->is_write ? "write" : "read");
	}
}

int kvm_handle_cp10_id(struct kvm_vcpu *vcpu, struct kvm_run *run)
{
	kvm_inject_undefined(vcpu);
	return 1;
}

int kvm_handle_cp_0_13_access(struct kvm_vcpu *vcpu, struct kvm_run *run)
{
	/*
	 * We can get here, if the host has been built without VFPv3 support,
	 * but the guest attempted a floating point operation.
	 */
	kvm_inject_undefined(vcpu);
	return 1;
}

int kvm_handle_cp14_load_store(struct kvm_vcpu *vcpu, struct kvm_run *run)
{
	kvm_inject_undefined(vcpu);
	return 1;
}

int kvm_handle_cp14_access(struct kvm_vcpu *vcpu, struct kvm_run *run)
{
	kvm_inject_undefined(vcpu);
	return 1;
}

static bool ignore_write(struct kvm_vcpu *vcpu, const struct coproc_params *p)
{
	return true;
}

static bool read_zero(struct kvm_vcpu *vcpu, const struct coproc_params *p)
{
	*vcpu_reg(vcpu, p->Rt1) = 0;
	return true;
}

static bool write_to_read_only(struct kvm_vcpu *vcpu,
			       const struct coproc_params *params)
{
	kvm_debug("CP15 write to read-only register at: %08x\n",
		  vcpu->arch.regs.pc);
	print_cp_instr(params);
	return false;
}

static bool read_from_write_only(struct kvm_vcpu *vcpu,
				 const struct coproc_params *params)
{
	kvm_debug("CP15 read to write-only register at: %08x\n",
		  vcpu->arch.regs.pc);
	print_cp_instr(params);
	return false;
}

/* A15 TRM 4.3.48: R/O WI. */
static bool access_l2ctlr(struct kvm_vcpu *vcpu,
			  const struct coproc_params *p,
			  const struct coproc_reg *r)
{
	if (p->is_write)
		return ignore_write(vcpu, p);

	*vcpu_reg(vcpu, p->Rt1) = vcpu->arch.cp15[c9_L2CTLR];
	return true;
}

static void reset_l2ctlr(struct kvm_vcpu *vcpu, const struct coproc_reg *r)
{
	u32 l2ctlr, ncores;

	asm volatile("mrc p15, 1, %0, c9, c0, 2\n" : "=r" (l2ctlr));
	l2ctlr &= ~(3 << 24);
	ncores = atomic_read(&vcpu->kvm->online_vcpus) - 1;
	l2ctlr |= (ncores & 3) << 24;

	vcpu->arch.cp15[c9_L2CTLR] = l2ctlr;
}

/* A15 TRM 4.3.49: R/O WI (even if NSACR.NS_L2ERR, a write of 1 is ignored). */
static bool access_l2ectlr(struct kvm_vcpu *vcpu,
			   const struct coproc_params *p,
			   const struct coproc_reg *r)
{
	if (p->is_write)
		return ignore_write(vcpu, p);

	*vcpu_reg(vcpu, p->Rt1) = 0;
	return true;
}

/* A15 TRM 4.3.60: R/O. */
static bool access_cbar(struct kvm_vcpu *vcpu,
			const struct coproc_params *p,
			const struct coproc_reg *r)
{
	if (p->is_write)
		return write_to_read_only(vcpu, p);
	return read_zero(vcpu, p);
}

/* A15 TRM 4.3.28: RO WI */
static bool access_actlr(struct kvm_vcpu *vcpu,
			 const struct coproc_params *p,
			 const struct coproc_reg *r)
{
	if (p->is_write)
		return ignore_write(vcpu, p);

	*vcpu_reg(vcpu, p->Rt1) = vcpu->arch.cp15[c1_ACTLR];
	return true;
}

static void reset_actlr(struct kvm_vcpu *vcpu, const struct coproc_reg *r)
{
	u32 actlr;

	/* ACTLR contains SMP bit: make sure you create all cpus first! */
	asm volatile("mrc p15, 0, %0, c1, c0, 1\n" : "=r" (actlr));
	/* Make the SMP bit consistent with the guest configuration */
	if (atomic_read(&vcpu->kvm->online_vcpus) > 1)
		actlr |= 1U << 6;
	else
		actlr &= ~(1U << 6);

	vcpu->arch.cp15[c1_ACTLR] = actlr;
}

/* See note at ARM ARM B1.14.4 */
static bool access_dcsw(struct kvm_vcpu *vcpu,
			const struct coproc_params *p,
			const struct coproc_reg *r)
{
	u32 val;
	int cpu;

	cpu = get_cpu();

	if (!p->is_write)
		return read_from_write_only(vcpu, p);

	cpumask_setall(&vcpu->arch.require_dcache_flush);
	cpumask_clear_cpu(cpu, &vcpu->arch.require_dcache_flush);

	/* If we were already preempted, take the long way around */
	if (cpu != vcpu->arch.last_pcpu) {
		flush_cache_all();
		goto done;
	}

	val = *vcpu_reg(vcpu, p->Rt1);

	switch (p->CRm) {
	case 6:			/* Upgrade DCISW to DCCISW, as per HCR.SWIO */
	case 14:		/* DCCISW */
		asm volatile("mcr p15, 0, %0, c7, c14, 2" : : "r" (val));
		break;

	case 10:		/* DCCSW */
		asm volatile("mcr p15, 0, %0, c7, c10, 2" : : "r" (val));
		break;
	}

done:
	put_cpu();

	return true;
}

/*
 * We could trap ID_DFR0 and tell the guest we don't support performance
 * monitoring.  Unfortunately the patch to make the kernel check ID_DFR0 was
 * NAKed, so it will read the PMCR anyway.
 *
 * Therefore we tell the guest we have 0 counters.  Unfortunately, we
 * must always support PMCCNTR (the cycle counter): we just RAZ/WI for
 * all PM registers, which doesn't crash the guest kernel at least.
 */
static bool pm_fake(struct kvm_vcpu *vcpu,
		    const struct coproc_params *p,
		    const struct coproc_reg *r)
{
	if (p->is_write)
		return ignore_write(vcpu, p);
	else
		return read_zero(vcpu, p);
}

#define access_pmcr pm_fake
#define access_pmcntenset pm_fake
#define access_pmcntenclr pm_fake
#define access_pmovsr pm_fake
#define access_pmselr pm_fake
#define access_pmceid0 pm_fake
#define access_pmceid1 pm_fake
#define access_pmccntr pm_fake
#define access_pmxevtyper pm_fake
#define access_pmxevcntr pm_fake
#define access_pmuserenr pm_fake
#define access_pmintenset pm_fake
#define access_pmintenclr pm_fake

/* Reset functions */
static void reset_unknown(struct kvm_vcpu *vcpu, const struct coproc_reg *r)
{
	BUG_ON(!r->reg);
	BUG_ON(r->reg >= ARRAY_SIZE(vcpu->arch.cp15));
	vcpu->arch.cp15[r->reg] = 0xdecafbad;
}

static void reset_val(struct kvm_vcpu *vcpu, const struct coproc_reg *r)
{
	BUG_ON(!r->reg);
	BUG_ON(r->reg >= ARRAY_SIZE(vcpu->arch.cp15));
	vcpu->arch.cp15[r->reg] = r->val;
}

static void reset_unknown64(struct kvm_vcpu *vcpu, const struct coproc_reg *r)
{
	BUG_ON(!r->reg);
	BUG_ON(r->reg + 1 >= ARRAY_SIZE(vcpu->arch.cp15));

	vcpu->arch.cp15[r->reg] = 0xdecafbad;
	vcpu->arch.cp15[r->reg+1] = 0xd0c0ffee;
}

static void reset_mpidr(struct kvm_vcpu *vcpu, const struct coproc_reg *r)
{
	/*
	 * Compute guest MPIDR:
	 * (Even if we present only one VCPU to the guest on an SMP
	 * host we don't set the U bit in the MPIDR, or vice versa, as
	 * revealing the underlying hardware properties is likely to
	 * be the best choice).
	 */
	vcpu->arch.cp15[c0_MPIDR] = (read_cpuid_mpidr() & ~MPIDR_CPUID)
		| (vcpu->vcpu_id & MPIDR_CPUID);
}

#define CRn(_x)		.CRn = _x
#define CRm(_x) 	.CRm = _x
#define Op1(_x) 	.Op1 = _x
#define Op2(_x) 	.Op2 = _x
#define is64		.is_64 = true
#define is32		.is_64 = false

/* Architected CP15 registers.
 * Important: Must sorted ascending by CRn, CRM, Op1, Op2
 */
static const struct coproc_reg cp15_regs[] = {
	/* TTBR0/TTBR1: swapped by interrupt.S. */
	{ CRm( 2), Op1( 0), is64, NULL, reset_unknown64, c2_TTBR0 },
	{ CRm( 2), Op1( 1), is64, NULL, reset_unknown64, c2_TTBR1 },

	/* TTBCR: swapped by interrupt.S. */
	{ CRn( 2), CRm( 0), Op1( 0), Op2( 0), is32,
			NULL, reset_val, c2_TTBCR, 0x00000000 },

	/* DACR: swapped by interrupt.S. */
	{ CRn( 3), CRm( 0), Op1( 0), Op2( 0), is32,
			NULL, reset_unknown, c3_DACR },

	/* DFSR/IFSR/ADFSR/AIFSR: swapped by interrupt.S. */
	{ CRn( 5), CRm( 0), Op1( 0), Op2( 0), is32,
			NULL, reset_unknown, c5_DFSR },
	{ CRn( 5), CRm( 0), Op1( 0), Op2( 1), is32,
			NULL, reset_unknown, c5_IFSR },
	{ CRn( 5), CRm( 1), Op1( 0), Op2( 0), is32,
			NULL, reset_unknown, c5_ADFSR },
	{ CRn( 5), CRm( 1), Op1( 0), Op2( 1), is32,
			NULL, reset_unknown, c5_AIFSR },

	/* DFAR/IFAR: swapped by interrupt.S. */
	{ CRn( 6), CRm( 0), Op1( 0), Op2( 0), is32,
			NULL, reset_unknown, c6_DFAR },
	{ CRn( 6), CRm( 0), Op1( 0), Op2( 2), is32,
			NULL, reset_unknown, c6_IFAR },
	/*
	 * DC{C,I,CI}SW operations:
	 */
	{ CRn( 7), CRm( 6), Op1( 0), Op2( 2), is32, access_dcsw},
	{ CRn( 7), CRm(10), Op1( 0), Op2( 2), is32, access_dcsw},
	{ CRn( 7), CRm(14), Op1( 0), Op2( 2), is32, access_dcsw},
	/*
	 * Dummy performance monitor implementation.
	 */
	{ CRn( 9), CRm(12), Op1( 0), Op2( 0), is32, access_pmcr},
	{ CRn( 9), CRm(12), Op1( 0), Op2( 1), is32, access_pmcntenset},
	{ CRn( 9), CRm(12), Op1( 0), Op2( 2), is32, access_pmcntenclr},
	{ CRn( 9), CRm(12), Op1( 0), Op2( 3), is32, access_pmovsr},
	{ CRn( 9), CRm(12), Op1( 0), Op2( 5), is32, access_pmselr},
	{ CRn( 9), CRm(12), Op1( 0), Op2( 6), is32, access_pmceid0},
	{ CRn( 9), CRm(12), Op1( 0), Op2( 7), is32, access_pmceid1},
	{ CRn( 9), CRm(13), Op1( 0), Op2( 0), is32, access_pmccntr},
	{ CRn( 9), CRm(13), Op1( 0), Op2( 1), is32, access_pmxevtyper},
	{ CRn( 9), CRm(13), Op1( 0), Op2( 2), is32, access_pmxevcntr},
	{ CRn( 9), CRm(14), Op1( 0), Op2( 0), is32, access_pmuserenr},
	{ CRn( 9), CRm(14), Op1( 0), Op2( 1), is32, access_pmintenset},
	{ CRn( 9), CRm(14), Op1( 0), Op2( 2), is32, access_pmintenclr},

	/* PRRR/NMRR (aka MAIR0/MAIR1): swapped by interrupt.S. */
	{ CRn(10), CRm( 2), Op1( 0), Op2( 0), is32,
			NULL, reset_unknown, c10_PRRR},
	{ CRn(10), CRm( 2), Op1( 0), Op2( 1), is32,
			NULL, reset_unknown, c10_NMRR},

	/* VBAR: swapped by interrupt.S. */
	{ CRn(12), CRm( 0), Op1( 0), Op2( 0), is32,
			NULL, reset_val, c12_VBAR, 0x00000000 },

	/* CONTEXTIDR/TPIDRURW/TPIDRURO/TPIDRPRW: swapped by interrupt.S. */
	{ CRn(13), CRm( 0), Op1( 0), Op2( 1), is32,
			NULL, reset_val, c13_CID, 0x00000000 },
	{ CRn(13), CRm( 0), Op1( 0), Op2( 2), is32,
			NULL, reset_unknown, c13_TID_URW },
	{ CRn(13), CRm( 0), Op1( 0), Op2( 3), is32,
			NULL, reset_unknown, c13_TID_URO },
	{ CRn(13), CRm( 0), Op1( 0), Op2( 4), is32,
			NULL, reset_unknown, c13_TID_PRIV },
};

/*
 * A15-specific CP15 registers.
 * Important: Must sorted ascending by CRn, CRM, Op1, Op2
 */
static const struct coproc_reg cp15_cortex_a15_regs[] = {
	/* MPIDR: we use VMPIDR for guest access. */
	{ CRn( 0), CRm( 0), Op1( 0), Op2( 5), is32,
			NULL, reset_mpidr, c0_MPIDR },

	/* SCTLR: swapped by interrupt.S. */
	{ CRn( 1), CRm( 0), Op1( 0), Op2( 0), is32,
			NULL, reset_val, c1_SCTLR, 0x00C50078 },
	/* ACTLR: trapped by HCR.TAC bit. */
	{ CRn( 1), CRm( 0), Op1( 0), Op2( 1), is32,
			access_actlr, reset_actlr, c1_ACTLR },
	/* CPACR: swapped by interrupt.S. */
	{ CRn( 1), CRm( 0), Op1( 0), Op2( 2), is32,
			NULL, reset_val, c1_CPACR, 0x00000000 },

	/*
	 * L2CTLR access (guest wants to know #CPUs).
	 */
	{ CRn( 9), CRm( 0), Op1( 1), Op2( 2), is32,
			access_l2ctlr, reset_l2ctlr, c9_L2CTLR },
	{ CRn( 9), CRm( 0), Op1( 1), Op2( 3), is32, access_l2ectlr},

	/* The Configuration Base Address Register. */
	{ CRn(15), CRm( 0), Op1( 4), Op2( 0), is32, access_cbar},
};

/* Get specific register table for this target. */
static const struct coproc_reg *get_target_table(unsigned target, size_t *num)
{
	switch (target) {
	case KVM_ARM_TARGET_CORTEX_A15:
		*num = ARRAY_SIZE(cp15_cortex_a15_regs);
		return cp15_cortex_a15_regs;
	default:
		*num = 0;
		return NULL;
	}
}

static const struct coproc_reg *find_reg(const struct coproc_params *params,
					 const struct coproc_reg table[],
					 unsigned int num)
{
	unsigned int i;

	for (i = 0; i < num; i++) {
		const struct coproc_reg *r = &table[i];

		if (params->is_64bit != r->is_64)
			continue;
		if (params->CRn != r->CRn)
			continue;
		if (params->CRm != r->CRm)
			continue;
		if (params->Op1 != r->Op1)
			continue;
		if (params->Op2 != r->Op2)
			continue;

		return r;
	}
	return NULL;
}

static int emulate_cp15(struct kvm_vcpu *vcpu,
			const struct coproc_params *params)
{
	size_t num;
	const struct coproc_reg *table, *r;

	trace_kvm_emulate_cp15_imp(params->Op1, params->Rt1, params->CRn,
				   params->CRm, params->Op2, params->is_write);

	table = get_target_table(vcpu->arch.target, &num);

	/* Search target-specific then generic table. */
	r = find_reg(params, table, num);
	if (!r)
		r = find_reg(params, cp15_regs, ARRAY_SIZE(cp15_regs));

	if (likely(r)) {
		/* If we don't have an accessor, we should never get here! */
		BUG_ON(!r->access);

		if (likely(r->access(vcpu, params, r))) {
			/* Skip instruction, since it was emulated */
			kvm_skip_instr(vcpu, (vcpu->arch.hsr >> 25) & 1);
			return 1;
		}
		/* If access function fails, it should complain. */
	} else {
		kvm_err("Unsupported guest CP15 access at: %08x\n",
			vcpu->arch.regs.pc);
		print_cp_instr(params);
	}
	kvm_inject_undefined(vcpu);
	return 1;
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

static void reset_coproc_regs(struct kvm_vcpu *vcpu,
			      const struct coproc_reg *table, size_t num)
{
	unsigned long i;

	for (i = 0; i < num; i++)
		if (table[i].reset)
			table[i].reset(vcpu, &table[i]);
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

/******************************************************************************
 * Userspace API
 *****************************************************************************/

/* Given a simple mask, get those bits. */
static inline u32 get_bits(u32 index, u32 mask)
{
	return (index & mask) >> (ffs(mask) - 1);
}

static void index_to_params(u32 index, struct coproc_params *params)
{
	if (get_bits(index, KVM_ARM_MSR_64_BIT_MASK)) {
		params->is_64bit = true;
		params->CRm = get_bits(index, KVM_ARM_MSR_64_CRM_MASK);
		params->Op1 = get_bits(index, KVM_ARM_MSR_64_OPC1_MASK);
		params->Op2 = 0;
		params->CRn = 0;
	} else {
		params->is_64bit = false;
		params->CRn = get_bits(index, KVM_ARM_MSR_32_CRN_MASK);
		params->CRm = get_bits(index, KVM_ARM_MSR_32_CRM_MASK);
		params->Op1 = get_bits(index, KVM_ARM_MSR_32_OPC1_MASK);
		params->Op2 = get_bits(index, KVM_ARM_MSR_32_OPC2_MASK);
	}
}

/* Decode an index value, and find the cp15 coproc_reg entry. */
static const struct coproc_reg *index_to_coproc_reg(struct kvm_vcpu *vcpu,
						    u32 index)
{
	size_t num;
	const struct coproc_reg *table, *r;
	struct coproc_params params;

	/* We only do cp15 for now. */
	if (get_bits(index, KVM_ARM_MSR_COPROC_MASK != 15))
		return NULL;

	index_to_params(index, &params);

	table = get_target_table(vcpu->arch.target, &num);
	r = find_reg(&params, table, num);
	if (!r)
		r = find_reg(&params, cp15_regs, ARRAY_SIZE(cp15_regs));

	/* Not saved in the cp15 array? */
	if (r && !r->reg)
		r = NULL;

	return r;
}

/*
 * These are the invariant cp15 registers: we let the guest see the host
 * versions of these, so they're part of the guest state.
 *
 * A future CPU may provide a mechanism to present different values to
 * the guest, or a future kvm may trap them.
 */
/* Unfortunately, there's no register-argument for mrc, so generate. */
#define FUNCTION_FOR32(crn, crm, op1, op2, name)			\
	static void get_##name(struct kvm_vcpu *v,			\
			       const struct coproc_reg *r)		\
	{								\
		u32 val;						\
									\
		asm volatile("mrc p15, " __stringify(op1)		\
			     ", %0, c" __stringify(crn)			\
			     ", c" __stringify(crm)			\
			     ", " __stringify(op2) "\n" : "=r" (val));	\
		((struct coproc_reg *)r)->val = val;			\
	}

FUNCTION_FOR32(0, 0, 0, 0, MIDR)
FUNCTION_FOR32(0, 0, 0, 1, CTR)
FUNCTION_FOR32(0, 0, 0, 2, TCMTR)
FUNCTION_FOR32(0, 0, 0, 3, TLBTR)
FUNCTION_FOR32(0, 0, 0, 6, REVIDR)
FUNCTION_FOR32(0, 1, 0, 0, ID_PFR0)
FUNCTION_FOR32(0, 1, 0, 1, ID_PFR1)
FUNCTION_FOR32(0, 1, 0, 2, ID_DFR0)
FUNCTION_FOR32(0, 1, 0, 3, ID_AFR0)
FUNCTION_FOR32(0, 1, 0, 4, ID_MMFR0)
FUNCTION_FOR32(0, 1, 0, 5, ID_MMFR1)
FUNCTION_FOR32(0, 1, 0, 6, ID_MMFR2)
FUNCTION_FOR32(0, 1, 0, 7, ID_MMFR3)
FUNCTION_FOR32(0, 2, 0, 0, ID_ISAR0)
FUNCTION_FOR32(0, 2, 0, 1, ID_ISAR1)
FUNCTION_FOR32(0, 2, 0, 2, ID_ISAR2)
FUNCTION_FOR32(0, 2, 0, 3, ID_ISAR3)
FUNCTION_FOR32(0, 2, 0, 4, ID_ISAR4)
FUNCTION_FOR32(0, 2, 0, 5, ID_ISAR5)
FUNCTION_FOR32(0, 0, 1, 0, CSSIDR)
FUNCTION_FOR32(0, 0, 1, 1, CLIDR)
FUNCTION_FOR32(0, 0, 1, 7, AIDR)

/* ->val is filled in by kvm_invariant_coproc_table_init() */
static struct coproc_reg invariant_cp15[] = {
	{ CRn( 0), CRm( 0), Op1( 0), Op2( 0), is32, NULL, get_MIDR },
	{ CRn( 0), CRm( 0), Op1( 0), Op2( 1), is32, NULL, get_CTR },
	{ CRn( 0), CRm( 0), Op1( 0), Op2( 2), is32, NULL, get_TCMTR },
	{ CRn( 0), CRm( 0), Op1( 0), Op2( 3), is32, NULL, get_TLBTR },
	{ CRn( 0), CRm( 0), Op1( 0), Op2( 6), is32, NULL, get_REVIDR },

	{ CRn( 0), CRm( 1), Op1( 0), Op2( 0), is32, NULL, get_ID_PFR0 },
	{ CRn( 0), CRm( 1), Op1( 0), Op2( 1), is32, NULL, get_ID_PFR1 },
	{ CRn( 0), CRm( 1), Op1( 0), Op2( 2), is32, NULL, get_ID_DFR0 },
	{ CRn( 0), CRm( 1), Op1( 0), Op2( 3), is32, NULL, get_ID_AFR0 },
	{ CRn( 0), CRm( 1), Op1( 0), Op2( 4), is32, NULL, get_ID_MMFR0 },
	{ CRn( 0), CRm( 1), Op1( 0), Op2( 5), is32, NULL, get_ID_MMFR1 },
	{ CRn( 0), CRm( 1), Op1( 0), Op2( 6), is32, NULL, get_ID_MMFR2 },
	{ CRn( 0), CRm( 1), Op1( 0), Op2( 7), is32, NULL, get_ID_MMFR3 },

	{ CRn( 0), CRm( 2), Op1( 0), Op2( 0), is32, NULL, get_ID_ISAR0 },
	{ CRn( 0), CRm( 2), Op1( 0), Op2( 1), is32, NULL, get_ID_ISAR1 },
	{ CRn( 0), CRm( 2), Op1( 0), Op2( 2), is32, NULL, get_ID_ISAR2 },
	{ CRn( 0), CRm( 2), Op1( 0), Op2( 3), is32, NULL, get_ID_ISAR3 },
	{ CRn( 0), CRm( 2), Op1( 0), Op2( 4), is32, NULL, get_ID_ISAR4 },
	{ CRn( 0), CRm( 2), Op1( 0), Op2( 5), is32, NULL, get_ID_ISAR5 },

	{ CRn( 0), CRm( 0), Op1( 1), Op2( 0), is32, NULL, get_CSSIDR },
	{ CRn( 0), CRm( 0), Op1( 1), Op2( 1), is32, NULL, get_CLIDR },
	{ CRn( 0), CRm( 0), Op1( 1), Op2( 7), is32, NULL, get_AIDR },
};

static int get_invariant_cp15(u32 index, u64 *val)
{
	struct coproc_params params;
	const struct coproc_reg *r;

	index_to_params(index, &params);
	r = find_reg(&params, invariant_cp15, ARRAY_SIZE(invariant_cp15));
	if (!r)
		return -ENOENT;

	*val = r->val;
	return 0;
}

static int set_invariant_cp15(u32 index, u64 val)
{
	struct coproc_params params;
	const struct coproc_reg *r;

	index_to_params(index, &params);
	r = find_reg(&params, invariant_cp15, ARRAY_SIZE(invariant_cp15));
	if (!r)
		return -ENOENT;

	/* This is what we mean by invariant: you can't change it. */
	if (r->val != val)
		return -EINVAL;

	return 0;
}

static int get_msr(struct kvm_vcpu *vcpu, u32 index, u64 *val)
{
	const struct coproc_reg *r;

	r = index_to_coproc_reg(vcpu, index);
	if (!r)
		return get_invariant_cp15(index, val);

	*val = vcpu->arch.cp15[r->reg];
	if (r->is_64)
		*val |= ((u64)vcpu->arch.cp15[r->reg+1]) << 32;
	return 0;
}

static int set_msr(struct kvm_vcpu *vcpu, u32 index, u64 val)
{
	const struct coproc_reg *r;

	r = index_to_coproc_reg(vcpu, index);
	if (!r)
		return set_invariant_cp15(index, val);

	vcpu->arch.cp15[r->reg] = val;
	if (r->is_64)
		vcpu->arch.cp15[r->reg+1] = (val >> 32);
	return 0;
}

/* Return user adddress to get/set value from. */
static u64 __user *get_umsr(struct kvm_msr_entry __user *uentry, u32 *idx)
{
	struct kvm_msr_entry entry;

	if (copy_from_user(&entry, uentry, sizeof(entry)))
		return NULL;
	*idx = entry.index;
	return &uentry->data;
}

/**
 * kvm_arm_get_msrs - copy one or more special registers to userspace.
 * @vcpu: the vcpu
 * @entries: the array of entries
 * @num: the number of entries
 */
int kvm_arm_get_msrs(struct kvm_vcpu *vcpu,
		     struct kvm_msr_entry __user *entries, u32 num)
{
	u32 i, index;
	u64 val;
	u64 __user *uval;
	int ret;

	for (i = 0; i < num; i++) {
		uval = get_umsr(&entries[i], &index);
		if (!uval)
			return -EFAULT;
		if ((ret = get_msr(vcpu, index, &val)) != 0)
			return ret;
		if (put_user(val, uval))
			return -EFAULT;
	}
	return 0;
}

/**
 * kvm_arm_set_msrs - copy one or more special registers from userspace.
 * @vcpu: the vcpu
 * @entries: the array of entries
 * @num: the number of entries
 */
int kvm_arm_set_msrs(struct kvm_vcpu *vcpu,
		     struct kvm_msr_entry __user *entries, u32 num)
{
	u32 i, index;
	u64 val;
	u64 __user *uval;
	int ret;

	for (i = 0; i < num; i++) {
		uval = get_umsr(&entries[i], &index);
		if (!uval)
			return -EFAULT;
		if (copy_from_user(&val, uval, sizeof(val)) != 0)
			return -EFAULT;
		if ((ret = set_msr(vcpu, index, val)) != 0)
			return ret;
	}
	return 0;
}

static int cmp_reg(const struct coproc_reg *i1, const struct coproc_reg *i2)
{
	BUG_ON(i1 == i2);
	if (!i1)
		return 1;
	else if (!i2)
		return -1;
	if (i1->CRn != i2->CRn)
		return i1->CRn - i2->CRn;
	if (i1->CRm != i2->CRm)
		return i1->CRm - i2->CRm;
	if (i1->Op1 != i2->Op1)
		return i1->Op1 - i2->Op1;
	return i1->Op2 - i2->Op2;
}

/* Puts in the position indicated by mask (assumes val fits in mask) */
static inline u32 set_bits(u32 val, u32 mask)
{
	return val << (ffs(mask)-1);
}

static u32 cp15_to_index(const struct coproc_reg *reg)
{
	u32 val = set_bits(15, KVM_ARM_MSR_COPROC_MASK);
	if (reg->is_64) {
		val |= set_bits(1, KVM_ARM_MSR_64_BIT_MASK);
		val |= set_bits(reg->Op1, KVM_ARM_MSR_64_OPC1_MASK);
		val |= set_bits(reg->CRm, KVM_ARM_MSR_64_CRM_MASK);
	} else {
		val |= set_bits(reg->Op1, KVM_ARM_MSR_32_OPC1_MASK);
		val |= set_bits(reg->Op2, KVM_ARM_MSR_32_OPC2_MASK);
		val |= set_bits(reg->CRm, KVM_ARM_MSR_32_CRM_MASK);
		val |= set_bits(reg->CRn, KVM_ARM_MSR_32_CRN_MASK);
	}
	return val;
}

static bool copy_reg_to_user(const struct coproc_reg *reg, u32 __user **uind)
{
	if (!*uind)
		return true;

	if (put_user(cp15_to_index(reg), *uind))
		return false;

	(*uind)++;
	return true;
}

/* Assumed ordered tables, see kvm_coproc_table_init. */
static int walk_msrs(struct kvm_vcpu *vcpu, u32 __user *uind)
{
	const struct coproc_reg *i1, *i2, *end1, *end2;
	unsigned int total = 0;
	size_t num;

	/* We check for duplicates here, to allow arch-specific overrides. */
	i1 = get_target_table(vcpu->arch.target, &num);
	end1 = i1 + num;
	i2 = cp15_regs;
	end2 = cp15_regs + ARRAY_SIZE(cp15_regs);

	BUG_ON(i1 == end1 || i2 == end2);

	/* Walk carefully, as both tables may refer to the same register. */
	while (i1 && i2) {
		int cmp = cmp_reg(i1, i2);
		/* target-specific overrides generic entry. */
		if (cmp <= 0) {
			/* Ignore registers we trap but don't save. */
			if (i1->reg) {
				if (!copy_reg_to_user(i1, &uind))
					return -EFAULT;
				total++;
			}
		} else {
			/* Ignore registers we trap but don't save. */
			if (i2->reg) {
				if (!copy_reg_to_user(i2, &uind))
					return -EFAULT;
				total++;
			}
		}

		if (cmp <= 0 && ++i1 == end1)
			i1 = NULL;
		if (cmp >= 0 && ++i2 == end2)
			i2 = NULL;
	}
	return total;
}

/**
 * kvm_arm_num_guest_msrs - how many registers do we present via KVM_GET_MSR
 *
 * This is for special registers, particularly cp15.
 */
unsigned long kvm_arm_num_guest_msrs(struct kvm_vcpu *vcpu)
{
	return ARRAY_SIZE(invariant_cp15) + walk_msrs(vcpu, (u32 __user *)NULL);
}

/**
 * kvm_arm_copy_msrindices - copy a series of coprocessor registers.
 *
 * This is for special registers, particularly cp15.
 */
int kvm_arm_copy_msrindices(struct kvm_vcpu *vcpu, u32 __user *uindices)
{
	unsigned int i;
	int err;

	/* First give them all the invariant registers' indices. */
	for (i = 0; i < ARRAY_SIZE(invariant_cp15); i++) {
		if (put_user(cp15_to_index(&invariant_cp15[i]), uindices))
			return -EFAULT;
		uindices++;
	}

	err = walk_msrs(vcpu, uindices);
	if (err > 0)
		err = 0;
	return err;
}

void kvm_coproc_table_init(void)
{
	unsigned int i;

	/* Make sure tables are unique and in order. */
	for (i = 1; i < ARRAY_SIZE(cp15_regs); i++)
		BUG_ON(cmp_reg(&cp15_regs[i-1], &cp15_regs[i]) >= 0);
	for (i = 1; i < ARRAY_SIZE(cp15_cortex_a15_regs); i++)
		BUG_ON(cmp_reg(&cp15_cortex_a15_regs[i-1],
			       &cp15_cortex_a15_regs[i]) >= 0);

	/* We abuse the reset function to overwrite the table itself. */
	for (i = 0; i < ARRAY_SIZE(invariant_cp15); i++)
		invariant_cp15[i].reset(NULL, &invariant_cp15[i]);
}

/**
 * kvm_reset_coprocs - sets cp15 registers to reset value
 * @vcpu: The VCPU pointer
 *
 * This function finds the right table above and sets the registers on the
 * virtual CPU struct to their architecturally defined reset values.
 */
void kvm_reset_coprocs(struct kvm_vcpu *vcpu)
{
	size_t num;
	const struct coproc_reg *table;

	/* Catch someone adding a register without putting in reset entry. */
	memset(vcpu->arch.cp15, 0x42, sizeof(vcpu->arch.cp15));

	/* Generic chip reset first (so target could override). */
	reset_coproc_regs(vcpu, cp15_regs, ARRAY_SIZE(cp15_regs));

	table = get_target_table(vcpu->arch.target, &num);
	reset_coproc_regs(vcpu, table, num);

	for (num = 1; num < nr_cp15_regs; num++)
		if (vcpu->arch.cp15[num] == 0x42424242)
			panic("Didn't reset vcpu->arch.cp15[%zi]", num);
}
