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

#ifndef __ARM_KVM_HOST_H__
#define __ARM_KVM_HOST_H__

#include <linux/string.h>
#include <linux/types.h>
#include <linux/list.h>
#include <asm/mmu_context.h>
#include <asm/ptrace.h>
#include <asm/kvm.h>

#define KVM_MAX_VCPUS 1
#define KVM_MEMORY_SLOTS 32
#define KVM_PRIVATE_MEM_SLOTS 4

/* We don't currently support large pages. */
#define KVM_NR_PAGE_SIZES		1
#define KVM_PAGES_PER_HPAGE		(1<<31)
#define KVM_COALESCED_MMIO_PAGE_OFFSET	1

struct kvm_vcpu;
u32* kvm_vcpu_reg(struct kvm_vcpu *vcpu, u8 reg_num, u32 mode);

struct kvm_arch {
};

#define VCPU_MODE(_vcpu) \
	(*((_vcpu)->arch.mode))

/* Get vcpu register for current mode */
#define vcpu_reg(_vcpu, _reg_num) \
	(*kvm_vcpu_reg((_vcpu), _reg_num, VCPU_MODE(_vcpu)))

/* Get vcpu register for specific mode */
#define vcpu_reg_m(_vcpu, _reg_num, _mode) \
	(*kvm_vcpu_reg(_vcpu, _reg_num, _mode))

#define vcpu_cpsr(_vcpu) \
	(_vcpu->arch.regs->cpsr)

/* Get vcpu SPSR for current mode */
#define vcpu_spsr(_vcpu) \
	(_vcpu->arch.regs->spsr[VCPU_MODE(_vcpu)])

/* Get vcpu SPSR for specific mode */
#define vcpu_spsr_m(_vcpu, _mode) \
	(_vcpu->arch.regs->spsr[_mode])

#define MODE_HAS_SPSR(_vcpu) \
	 ((VCPU_MODE(_vcpu)) < MODE_USER)

#define VCPU_MODE_PRIV(_vcpu) \
	(((VCPU_MODE(_vcpu)) == MODE_USER) ? 0 : 1)

#define VCPU_DOMAIN_VAL(_vcpu, _dom) \
	((vcpu->arch.cp15.c3_DACR >> (_dom*2)) & 0x3)

#define VCPU_HOST_EXCP_BASE(_vcpu) \
	(vcpu->arch.host_vectors_high ? \
		EXCEPTION_VECTOR_HIGH : EXCEPTION_VECTOR_LOW)

#define VCPU_GUEST_EXCP_BASE(_vcpu) \
	((vcpu->arch.cp15.c1_CR & CP15_CR_V_BIT) ? \
	 	EXCEPTION_VECTOR_HIGH : EXCEPTION_VECTOR_LOW)

typedef struct kvm_shadow_pgtable {
	u32 *pgd; /* Pointer to first level-1 descriptor */
	hpa_t pa; /* Host physical address */
	unsigned int id; /* Process id, genereated by __new_asid() */
	gva_t guest_ttbr; /* The guest TTBR, NULL == guest MMU disabled */
	struct list_head list;
} kvm_shadow_pgtable;

#define EXCEPTION_NONE      0
#define EXCEPTION_RESET     0x80
#define EXCEPTION_UNDEFINED 0x40
#define EXCEPTION_SOFTWARE  0x20
#define EXCEPTION_PREFETCH  0x10
#define EXCEPTION_DATA      0x08
#define EXCEPTION_IMPRECISE 0x04
#define EXCEPTION_IRQ       0x02
#define EXCEPTION_FIQ       0x01

/*
 * The order, size and offsets of the fields are important here as
 * the world-switch code in arm_interrupts.S rely on the exact layout
 * of this struct.
 */
struct kvm_vcpu_regs {
	u32 fiq_reg[5];		/* FIQ  Mode r8-r12 */
	u32 usr_reg[5];		/* USER Mode r8-r12 */
	u32 banked_fiq[2];	/* FIQ r13,r14 */
	u32 banked_irq[2];	/* IRQ r13,r14 */
	u32 banked_svc[2];	/* SVC r13,r14 */
	u32 banked_abt[2];	/* ABORT r13,r14 */
	u32 banked_und[2];	/* UNDEFINED r13,r14 */
	u32 banked_usr[2];	/* USER r13,r14 */
	u32 shared_reg[8];	/* Shared r0-r7 */
	u32 r15;		/* r15 */
	u32 cpsr;		/* Guest emulated CPSR */
	u32 spsr[5];		/* Guest SPSR per-mode */
} __packed;

/*
 * Shared page layout
 */
struct shared_page {
	unsigned long shared_sp;
	unsigned long return_ptr;
	unsigned long irq_svc_address;
	unsigned long host_sp;
	unsigned long exception_index;
	unsigned long execution_CPSR;
	unsigned long host_regs[16];
	unsigned long host_CPSR;
	unsigned long host_SPSR;
	unsigned long host_ttbr;
	struct kvm_vcpu_regs vcpu_regs; /* Virtual CPU registers */
	unsigned long vcpu_mode;
	unsigned long shadow_ttbr;
	unsigned long guest_dac;
	unsigned long guest_asid;
	unsigned long host_dac;
	unsigned long host_asid;
	unsigned long guest_instr;	/* Inst. causing the excpt. */
	unsigned long orig_instr;	/* Instr. following SWI instr. */
	unsigned long clear_tlb;
};

struct kvm_vcpu_arch {
	/* Pointer to regs struct on shared page */
	struct kvm_vcpu_regs *regs;

	/* Pointer to cached mode on shared page */
	unsigned long *mode;

	/* System control coprocessor (cp15) */
	struct {
		u32 c0_MIDR;		/* Main ID Register */
		u32 c0_CTR;		/* Cache Type Register */
		u32 c0_TCMTR;   	/* Tightly Coupled Memory Type Register */
		u32 c0_TLBTR;   	/* TLB Type Register */
		u32 c1_CR;		/* Control Register */
		u32 c1_ACR;		/* Auxilliary Control Register */
		u32 c1_CAR;		/* Coprocessor Access Register */
		u32 c2_TTBR0;		/* Translation Table Base Register 0 */
		u32 c2_TTBR1;		/* Translation Table Base Register 1 */
		u32 c2_TTBR_CR;		/* Translation Table Base Register Control */
		u32 c3_DACR;		/* Domain Access Control Register */
		u32 c5_DFSR;		/* Fault Status Register */
		u32 c5_IFSR;		/* Fault Status Register */
		u32 c6_FAR;		/* Fault Address Register */
		u32 c7_CDSR;		/* Cache Dirty Status Register */
		u32 c7_RBTSR;		/* Read Block Transfer Status Register */
		u32 c9_DCLR;		/* Data Cache Lockdown Register */
		u32 c9_ICLR;		/* Instruction Cachce Lockdown Register */
		u32 c9_DTCMR;		/* Data TCM Region */
		u32 c9_ITCMR;		/* Instruction TCM Region */
		u32 c10_TLBLR;		/* TLB Lockdown Register */
		u32 c13_FCSER;		/* Fast Context Switch Extension Register */
		u32 c13_CID;		/* Context ID Register */
		u32 c13_TIDURW;		/* User Read/Write Thread and Process ID */
		u32 c13_TIDURO;		/* User Read-only Thread and Process ID */
		u32 c13_TIDPO;		/* Privileged only Thread and Process ID */
	} cp15;

	u32 guest_exception;  		/* Hardware exception that exited the guest */
	u32 exception_pending;  	/* Exception to raise after emulation */

	/* Host status */
	u32 host_far;		/* Fault access register */
	u32 host_fsr;		/* Fault status register */
	u32 host_ifsr;		/* Fault status register */

	/* MMU related fields */
	u32 *shared_page_alloc; /* Kernel-allocated address for shared page */
	struct shared_page *shared_page;
	u32 *guest_vectors;

	unsigned int host_asid;
	kvm_shadow_pgtable *shadow_pgtable;
	struct list_head shadow_pgtable_list;
	hpa_t host_pgd_pa;
	int host_vectors_high;

	/*
	 * Used to keep correct access permissions for pages which l1 desc.
	 * conincide with that of shared page or the irq vector page.
	 */
	u32 shared_page_guest_domain;
	u32 vector_page_guest_domain;
	u32 shared_page_shadow_ap[256];
	u32 vector_page_shadow_ap[256];

	u32 *l2_unused_pt;

	/* shared page pointers */
	int (*run)(void *vcpu);

	/* IO related fields */
	u32 mmio_rd;

	/* Misc. fields */
	u32 wait_for_interrupts;

	struct kvm_run *kvm_run;
};

struct kvm_vm_stat {
	u32 remote_tlb_flush;
};

struct kvm_vcpu_stat {
	u32 sum_exits;
	u32 mmio_exits;
	u32 dcr_exits;
	u32 signal_exits;
	u32 light_exits;
	/* Account for special types of light exits: */
	u32 itlb_real_miss_exits;
	u32 itlb_virt_miss_exits;
	u32 dtlb_real_miss_exits;
	u32 dtlb_virt_miss_exits;
	u32 syscall_exits;
	u32 isi_exits;
	u32 dsi_exits;
	u32 emulated_inst_exits;
	u32 dec_exits;
	u32 ext_intr_exits;
	u32 halt_wakeup;
};


/*
 * Pre ARMv5: Return CP 15, TTBR
 * ARMv6 and higher: Return the TTBR based on the MVA and the value in
 * the TTBR control register
 */
static inline gpa_t kvm_guest_ttbr(struct kvm_vcpu_arch *vcpu_arch, gva_t gva)
{
	unsigned int n = 0;

	if (cpu_architecture() >= CPU_ARCH_ARMv6) {
		BUG_ON(vcpu_arch->cp15.c2_TTBR_CR & ~0x7);
		n = vcpu_arch->cp15.c2_TTBR_CR & 0x7;

		if (n != 0 && (gva >> (32-n)) == 0)
			return vcpu_arch->cp15.c2_TTBR1 & (~0 << 14);

		return vcpu_arch->cp15.c2_TTBR0 & (~0 << (14 - n));
	}
	return vcpu_arch->cp15.c2_TTBR0 & (~0 << 14);
}

#endif /* __ARM_KVM_HOST_H__ */
