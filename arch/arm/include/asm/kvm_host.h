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

#ifndef __ARM_KVM_HOST_H__
#define __ARM_KVM_HOST_H__

#include <asm/kvm.h>
#include <asm/fpstate.h>

#define KVM_MAX_VCPUS NR_CPUS
#define KVM_MEMORY_SLOTS 32
#define KVM_PRIVATE_MEM_SLOTS 4
#define KVM_COALESCED_MMIO_PAGE_OFFSET 1
#define KVM_HAVE_ONE_REG

#include <asm/kvm_vgic.h>
#include <asm/kvm_arch_timer.h>

#define KVM_VCPU_MAX_FEATURES 0

/* We don't currently support large pages. */
#define KVM_HPAGE_GFN_SHIFT(x)	0
#define KVM_NR_PAGE_SIZES	1
#define KVM_PAGES_PER_HPAGE(x)	(1UL<<31)

struct kvm_vcpu;
u32 *kvm_vcpu_reg(struct kvm_vcpu *vcpu, u8 reg_num, u32 mode);
int kvm_target_cpu(void);
int kvm_reset_vcpu(struct kvm_vcpu *vcpu);
void kvm_reset_coprocs(struct kvm_vcpu *vcpu);

struct kvm_arch {
	/* The VMID generation used for the virt. memory system */
	u64    vmid_gen;
	u32    vmid;

	/* Stage-2 page table */
	pgd_t *pgd;

	/* VTTBR value associated with above pgd and vmid */
	u64    vttbr;

	/* Interrupt controller */
	struct vgic_dist	vgic;

	/* Timer */
	struct arch_timer_kvm	timer;
};

#define KVM_NR_MEM_OBJS     40

/*
 * We don't want allocation failures within the mmu code, so we preallocate
 * enough memory for a single page fault in a cache.
 */
struct kvm_mmu_memory_cache {
	int nobjs;
	void *objects[KVM_NR_MEM_OBJS];
};

/* 0 is reserved as an invalid value. */
enum cp15_regs {
	c0_MPIDR=1,		/* MultiProcessor ID Register */
	c0_CSSELR,		/* Cache Size Selection Register */
	c1_SCTLR,		/* System Control Register */
	c1_ACTLR,		/* Auxilliary Control Register */
	c1_CPACR,		/* Coprocessor Access Control */
	c2_TTBR0,		/* Translation Table Base Register 0 */
	c2_TTBR0_high,		/* TTBR0 top 32 bits */
	c2_TTBR1,		/* Translation Table Base Register 1 */
	c2_TTBR1_high,		/* TTBR1 top 32 bits */
	c2_TTBCR,		/* Translation Table Base Control R. */
	c3_DACR,		/* Domain Access Control Register */
	c5_DFSR,		/* Data Fault Status Register */
	c5_IFSR,		/* Instruction Fault Status Register */
	c5_ADFSR,		/* Auxilary Data Fault Status Register */
	c5_AIFSR,		/* Auxilary Instruction Fault Status Register */
	c6_DFAR,		/* Data Fault Address Register */
	c6_IFAR,		/* Instruction Fault Address Register */
	c9_L2CTLR,		/* Cortex A15 L2 Control Register */
	c10_PRRR,		/* Primary Region Remap Register */
	c10_NMRR,		/* Normal Memory Remap Register */
	c12_VBAR,		/* Vector Base Address Register */
	c13_CID,		/* Context ID Register */
	c13_TID_URW,		/* Thread ID, User R/W */
	c13_TID_URO,		/* Thread ID, User R/O */
	c13_TID_PRIV,		/* Thread ID, Priveleged */

	nr_cp15_regs
};

struct kvm_vcpu_arch {
	struct kvm_regs regs;

	u32 target; /* Currently KVM_ARM_TARGET_CORTEX_A15 */
	DECLARE_BITMAP(features, KVM_VCPU_MAX_FEATURES);

	/* System control coprocessor (cp15) */
	u32 cp15[nr_cp15_regs];

	/* The CPU type we expose to the VM */
	u32 midr;

	/* Exception Information */
	u32 hsr;		/* Hyp Syndrom Register */
	u32 hdfar;		/* Hyp Data Fault Address Register */
	u32 hifar;		/* Hyp Inst. Fault Address Register */
	u32 hpfar;		/* Hyp IPA Fault Address Register */

	/* Floating point registers (VFP and Advanced SIMD/NEON) */
	struct vfp_hard_struct vfp_guest;
	struct vfp_hard_struct *vfp_host;

	/* VGIC state */
	struct vgic_cpu vgic_cpu;
	struct arch_timer_cpu timer_cpu;

	/*
	 * Anything that is not used directly from assembly code goes
	 * here.
	 */
	/* dcache set/way operation pending */
	int last_pcpu;
	cpumask_t require_dcache_flush;

	/* Don't run the guest: see copy_current_insn() */
	bool pause;

	/* IO related fields */
	struct {
		bool sign_extend;	/* for byte/halfword loads */
		u32  rd;
	} mmio;

	/* Interrupt related fields */
	u32 irq_lines;		/* IRQ and FIQ levels */

	/* Hyp exception information */
	u32 hyp_pc;		/* PC when exception was taken from Hyp mode */

	/* Cache some mmu pages needed inside spinlock regions */
	struct kvm_mmu_memory_cache mmu_page_cache;
};

struct kvm_vm_stat {
	u32 remote_tlb_flush;
};

struct kvm_vcpu_stat {
	u32 halt_wakeup;
};

struct kvm_vcpu_init;
int kvm_vcpu_set_target(struct kvm_vcpu *vcpu,
			const struct kvm_vcpu_init *init);
unsigned long kvm_arm_num_regs(struct kvm_vcpu *vcpu);
int kvm_arm_copy_reg_indices(struct kvm_vcpu *vcpu, u64 __user *indices);
struct kvm_one_reg;
int kvm_arm_get_reg(struct kvm_vcpu *vcpu, const struct kvm_one_reg *reg);
int kvm_arm_set_reg(struct kvm_vcpu *vcpu, const struct kvm_one_reg *reg);

#define KVM_ARCH_WANT_MMU_NOTIFIER
struct kvm;
int kvm_unmap_hva(struct kvm *kvm, unsigned long hva);
int kvm_unmap_hva_range(struct kvm *kvm,
			unsigned long start, unsigned long end);
void kvm_set_spte_hva(struct kvm *kvm, unsigned long hva, pte_t pte);

unsigned long kvm_arm_num_regs(struct kvm_vcpu *vcpu);
int kvm_arm_copy_reg_indices(struct kvm_vcpu *vcpu, u64 __user *indices);

/* We do not have shadow page tables, hence the empty hooks */
static inline int kvm_age_hva(struct kvm *kvm, unsigned long hva)
{
	return 0;
}

static inline int kvm_test_age_hva(struct kvm *kvm, unsigned long hva)
{
	return 0;
}

struct kvm_vcpu *kvm_arm_get_running_vcpu(void);
struct kvm_vcpu __percpu **kvm_get_running_vcpus(void);

int kvm_arm_copy_coproc_indices(struct kvm_vcpu *vcpu, u64 __user *uindices);
unsigned long kvm_arm_num_coproc_regs(struct kvm_vcpu *vcpu);
struct kvm_one_reg;
int kvm_arm_coproc_get_reg(struct kvm_vcpu *vcpu, const struct kvm_one_reg *);
int kvm_arm_coproc_set_reg(struct kvm_vcpu *vcpu, const struct kvm_one_reg *);
#endif /* __ARM_KVM_HOST_H__ */
