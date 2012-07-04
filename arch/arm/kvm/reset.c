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
#include <linux/compiler.h>
#include <linux/errno.h>
#include <linux/sched.h>
#include <linux/kvm_host.h>
#include <linux/kvm.h>

#include <asm/unified.h>
#include <asm/ptrace.h>
#include <asm/cputype.h>
#include <asm/kvm_arm.h>

#define CT_ASSERT(expr, name) extern char name[(expr) ? 1 : -1]
#define CP15_REGS_ASSERT(_array, _name) \
	CT_ASSERT((sizeof(_array) / sizeof(_array[0])) == nr_cp15_regs, _name)
#define UNKNOWN 0xdecafbad

/******************************************************************************
 * Cortex-A15 Register Reset Values
 */

static const int a15_max_cpu_idx = 3;

static struct kvm_vcpu_regs a15_regs_reset = {
	.cpsr = SVC_MODE | PSR_A_BIT | PSR_I_BIT | PSR_F_BIT,
};

static u32 a15_cp15_regs_reset[][2] = {
	{ c0_MIDR,		0x412FC0F0 },
	{ c0_MPIDR,		0x00000000 }, /* see kvm_arch_vcpu_init */
	{ c1_SCTLR,		0x00C50078 },
	{ c1_ACTLR,		0x00000000 },
	{ c1_CPACR,		0x00000000 },
	{ c2_TTBR0,		UNKNOWN },
	{ c2_TTBR0_high,	UNKNOWN },
	{ c2_TTBR1,		UNKNOWN },
	{ c2_TTBR1_high,	UNKNOWN },
	{ c2_TTBCR,		0x00000000 },
	{ c3_DACR,		UNKNOWN },
	{ c5_DFSR,		UNKNOWN },
	{ c5_IFSR,		UNKNOWN },
	{ c5_ADFSR,		UNKNOWN },
	{ c5_AIFSR,		UNKNOWN },
	{ c6_DFAR,		UNKNOWN },
	{ c6_IFAR,		UNKNOWN },
	{ c10_PRRR,		0x00098AA4 },
	{ c10_NMRR,		0x44E048E0 },
	{ c12_VBAR,		0x00000000 },
	{ c13_CID,		0x00000000 },
	{ c13_TID_URW,		UNKNOWN },
	{ c13_TID_URO,		UNKNOWN },
	{ c13_TID_PRIV,		UNKNOWN },
};
CP15_REGS_ASSERT(a15_cp15_regs_reset, a15_cp15_regs_reset_init);

static void a15_reset_vcpu(struct kvm_vcpu *vcpu)
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


/*******************************************************************************
 * Exported reset function
 */

/**
 * kvm_reset_vcpu - sets core registers and cp15 registers to reset value
 * @vcpu: The VCPU pointer
 *
 * This function finds the right table above and sets the registers on the
 * virtual CPU struct to their architectually defined reset values.
 */
int kvm_reset_vcpu(struct kvm_vcpu *vcpu)
{
	unsigned int i;
	struct kvm_vcpu_regs *cpu_reset;
	u32 (*cp15_reset)[2];
	void (*cpu_reset_vcpu)(struct kvm_vcpu *vcpu);

	switch (kvm_target_cpu()) {
	case CORTEX_A15:
		if (vcpu->vcpu_id > a15_max_cpu_idx)
			return -EINVAL;
		cpu_reset = &a15_regs_reset;
		cp15_reset = a15_cp15_regs_reset;
		cpu_reset_vcpu = a15_reset_vcpu;
		break;
	default:
		return -ENODEV;
	}

	/* Reset core registers */
	memcpy(&vcpu->arch.regs, cpu_reset, sizeof(vcpu->arch.regs));

	/* Reset CP15 registers */
	for (i = 0; i < nr_cp15_regs; i++) {
		if (cp15_reset[i][0] != i) {
			kvm_err("CP15 field %d is %d, expected %d\n",
				i, cp15_reset[i][0], i);
			return -ENXIO;
		}
		vcpu->arch.cp15[i] = cp15_reset[i][1];
	}

	/* Physical CPU specific runtime reset operations */
	cpu_reset_vcpu(vcpu);

	return 0;
}
