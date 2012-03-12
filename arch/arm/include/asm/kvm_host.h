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

#define KVM_MAX_VCPUS 1
#define KVM_MEMORY_SLOTS 32
#define KVM_PRIVATE_MEM_SLOTS 4
#define KVM_COALESCED_MMIO_PAGE_OFFSET 1

/* We don't currently support large pages. */
#define KVM_HPAGE_GFN_SHIFT(x)	0
#define KVM_NR_PAGE_SIZES	1
#define KVM_PAGES_PER_HPAGE(x)	(1UL<<31)

struct kvm_vcpu;
u32 *kvm_vcpu_reg(struct kvm_vcpu *vcpu, u8 reg_num, u32 mode);

struct kvm_arch {
	/* The VMID used for the virt. memory system */
	u64    vmid;

	/* 1-level 2nd stage table and lock */
	struct mutex pgd_mutex;
	pgd_t *pgd;

	/* VTTBR value associated with above pgd and vmid */
	u64    vttbr;
};

#define EXCEPTION_NONE      0
#define EXCEPTION_RESET     0x80
#define EXCEPTION_UNDEFINED 0x40
#define EXCEPTION_SOFTWARE  0x20
#define EXCEPTION_PREFETCH  0x10
#define EXCEPTION_DATA      0x08
#define EXCEPTION_IMPRECISE 0x04
#define EXCEPTION_IRQ       0x02
#define EXCEPTION_FIQ       0x01

struct kvm_vcpu_regs {
	u32 usr_regs[15];	/* R0_usr - R14_usr */
	u32 svc_regs[3];	/* SP_svc, LR_svc, SPSR_svc */
	u32 abt_regs[3];	/* SP_abt, LR_abt, SPSR_abt */
	u32 und_regs[3];	/* SP_und, LR_und, SPSR_und */
	u32 irq_regs[3];	/* SP_irq, LR_irq, SPSR_irq */
	u32 fiq_regs[8];	/* R8_fiq - R14_fiq, SPSR_fiq */
	u32 pc;			/* The program counter (r15) */
	u32 cpsr;		/* The guest CPSR */
} __packed;

enum cp15_regs {
	c0_MIDR,		/* Main ID Register */
	c0_MPIDR,		/* MultiProcessor ID Register */
	c1_SCTLR,		/* System Control Register */
	c1_ACTLR,		/* Auxilliary Control Register */
	c1_CPACR,		/* Coprocessor Access Control */
	c2_TTBR0,		/* Translation Table Base Register 0 */
	c2_TTBR0_high,		/* TTBR0 top 32 bits */
	c2_TTBR1,		/* Translation Table Base Register 1 */
	c2_TTBR1_high,		/* TTBR1 top 32 bits */
	c2_TTBCR,		/* Translation Table Base Control R. */
	c3_DACR,		/* Domain Access Control Register */
	c10_PRRR,		/* Primary Region Remap Register */
	c10_NMRR,		/* Normal Memory Remap Register */
	c13_CID,		/* Context ID Register */
	c13_TID_URW,		/* Thread ID, User R/W */
	c13_TID_URO,		/* Thread ID, User R/O */
	c13_TID_PRIV,		/* Thread ID, Priveleged */

	nr_cp15_regs
};

struct kvm_vcpu_arch {
	struct kvm_vcpu_regs regs;

	/* System control coprocessor (cp15) */
	u32 cp15[nr_cp15_regs];

	/* Exception Information */
	u32 hsr;		/* Hyp Syndrom Register */
	u32 hdfar;		/* Hyp Data Fault Address Register */
	u32 hifar;		/* Hyp Inst. Fault Address Register */
	u32 hpfar;		/* Hyp IPA Fault Address Register */

	/* IO related fields */
	u32 mmio_rd;

	/* Interrupt related fields */
	u32 irq_lines;		/* IRQ and FIQ levels */
	u32 wait_for_interrupts;
};

struct kvm_vm_stat {
	u32 remote_tlb_flush;
};

struct kvm_vcpu_stat {
	u32 halt_wakeup;
};

#endif /* __ARM_KVM_HOST_H__ */
