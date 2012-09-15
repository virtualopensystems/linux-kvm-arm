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
 * Important: Must be sorted ascending by CRn, CRM, Op1, Op2
 */
static const struct coproc_reg cp15_regs[] = {
	/* CSSELR: swapped by interrupt.S. */
	{ CRn( 0), CRm( 0), Op1( 2), Op2( 0), is32,
			NULL, reset_unknown, c0_CSSELR },

	/* TTBR0/TTBR1: swapped by interrupt.S. */
	{ CRm( 2), Op1( 0), is64, NULL, reset_unknown64, c2_TTBR0 },
	{ CRm( 2), Op1( 1), is64, NULL, reset_unknown64, c2_TTBR1 },

	/* TTBCR: swapped by interrupt.S. */
	{ CRn( 2), CRm( 0), Op1( 0), Op2( 2), is32,
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
 * Important: Must be sorted ascending by CRn, CRM, Op1, Op2
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

static int cmp_reg(const struct coproc_reg *i1, const struct coproc_reg *i2)
{
	if (i1->CRn != i2->CRn)
		return i1->CRn - i2->CRn;
	if (i1->CRm != i2->CRm)
		return i1->CRm - i2->CRm;
	if (i1->Op1 != i2->Op1)
		return i1->Op1 - i2->Op1;
	return i1->Op2 - i2->Op2;
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
