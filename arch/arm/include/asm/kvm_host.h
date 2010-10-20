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
 * Copyright 
 *
 * Authors: 
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

struct kvm_arch {
};

#define VCPU_REG(_vcpu, _reg_num) \
	(*kvm_vcpu_reg(&_vcpu->arch, _reg_num))

#define VCPU_SPSR(_vcpu) \
	(_vcpu->arch.banked_spsr[_vcpu->arch.mode])

#define MODE_HAS_SPSR(_vcpu) (_vcpu->arch.mode < MODE_USER)

#define VCPU_MODE_PRIV(_vcpu) \
	((_vcpu->arch.mode == MODE_USER) \
	 ? 0 : 1)

#define VCPU_DOMAIN_VAL(_vcpu, _dom) \
	((vcpu->arch.cp15.c3_DACR >> (_dom*2)) & 0x3)

#define VCPU_HOST_EXCP_BASE(_vcpu) \
	(vcpu->arch.host_vectors_high ? \
		EXCEPTION_VECTOR_HIGH : EXCEPTION_VECTOR_LOW)

#define VCPU_GUEST_EXCP_BASE(_vcpu) \
	((vcpu->arch.cp15.c1_CR & CP15_CR_V_BIT) ? \
	 	EXCEPTION_VECTOR_HIGH : EXCEPTION_VECTOR_LOW)

struct kvm_basic_block {
	gva_t start_addr;
	gva_t end_addr;
	gva_t branch_addr; /* source of branch if needed */
	struct list_head list;
};

struct kvm_trans_orig {
	gva_t addr;
	u32 instr;
	struct list_head list;
};

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
 * Shared page layout
 */
struct shared_page {
	unsigned long shared_sp;
	unsigned long return_ptr;
	unsigned long host_sp;
	unsigned long exception_index;
	unsigned long guest_regs[16];
	unsigned long guest_CPSR;
	unsigned long host_regs[16];
	unsigned long host_CPSR;
	unsigned long host_SPSR;
	unsigned long host_ttbr;
	unsigned long shadow_ttbr;
	unsigned long guest_dac;
	unsigned long guest_asid;
	unsigned long host_dac;
	unsigned long host_asid;
	unsigned long guest_instr;	/* Inst. causing the excpt. */
	unsigned long orig_instr;	/* Instr. following SWI instr. */
};

struct kvm_vcpu_arch {
	/* The user mode and shared registers */
	u32 regs[16];		

	/* The CPSR */
	u32 cpsr;

	/* Quickly determine mode */
	u8 mode;			

	/* Banked registers.  */
	u32 fiq_regs[5];		   /* The FIQ regs R8-R12 */
	u32 banked_r13[5];		/* The R13 for each priv. mode */
	u32 banked_r14[5];		/* The R14 for each priv. mode */
	u32 banked_spsr[5];		/* The SPSR for each supported mode */

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

#ifdef KVMARM_BIN_TRANSLATE 
	u32 trans_start;		/* Guest address translation started at */
	u32 trans_numTrans;		/* Number of guest instructions translated */
	u32 *trans_untrans_instrs;	/* Guest's untranslated instr., host storage */
	struct list_head trans_head;	/* Head of blocks to translate */
	struct list_head trans_orig;	/* Original instructions */
#endif

	u8 guest_exception;  	/* Hardware exception that exited the guest */
	u8 exception_pending;  	/* Exception to raise after emulation */

	/* Host status */
	u32 host_far;		/* Fault access register */
	u32 host_fsr;		/* Fault status register */
	u32 host_ifsr;		/* Fault status register */

	/* MMU related fields */
	u32 *shared_page_alloc;
	struct shared_page *shared_page;
	u32 *guest_vectors;

	kvm_shadow_pgtable *shadow_pgtable;
	struct list_head shadow_pgtable_list;
	hpa_t host_pgd_pa;
	int host_vectors_high;

	/* 
	 * Used to keep correct access permissions for pages which l1 desc.
	 * conincide with that of shared page or the irq vector page.
	 */
	u8 shared_page_guest_domain;
	u8 vector_page_guest_domain;
	u8 shared_page_shadow_ap[256];
	u8 vector_page_shadow_ap[256];

	u32 *l2_unused_pt;

	/* shared page pointers */
	int (*run)(void *vcpu);

	/* IO related fields */
	u8 mmio_rd;

	/* Misc. fields */
	u8 wait_for_interrupts;

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
 * Return a pointer to the register number valid in the current mode of
 * the virtual CPU.
 */
static inline u32* kvm_vcpu_reg(struct kvm_vcpu_arch *vcpu_arch,
			        u8 reg_num)
{
	if (reg_num == 13 && vcpu_arch->mode != MODE_USER)
		return &(vcpu_arch->banked_r13[vcpu_arch->mode]);

	if (reg_num == 14 && vcpu_arch->mode != MODE_USER)
		return &(vcpu_arch->banked_r14[vcpu_arch->mode]);

	if (reg_num >= 8 && reg_num < 15 &&vcpu_arch->mode == MODE_FIQ)
		return &(vcpu_arch->fiq_regs[reg_num - 8]);

	return &(vcpu_arch->regs[reg_num]);
}

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

/*
 * Dump virtual CPU state into kernel log buffer
 */
static inline void kvm_dump_vcpu_state(struct kvm_vcpu_arch *vcpu_arch)
{
	int i;
	char *mode = NULL;

	switch (vcpu_arch->mode) {
		case MODE_USER: mode = "USR"; break;
		case MODE_FIQ: mode = "FIQ"; break;
		case MODE_IRQ: mode = "IRQ"; break;
		case MODE_SVC: mode = "SVC"; break;
		case MODE_ABORT: mode = "ABT"; break;
		case MODE_UNDEF: mode = "UND"; break;
		case MODE_SYSTEM: mode = "SYS"; break;
	}

	printk(KERN_DEBUG "\n");
	printk(KERN_DEBUG "\n");
	printk(KERN_DEBUG "=================================================\n");
	printk(KERN_DEBUG "Virtual CPU state:\n");
	printk(KERN_DEBUG "\n");
	for (i = 0; i <= 15; i++) {
		printk(KERN_DEBUG "user regs[%u]:\t0x%08x\t0x%08x\t0x%08x\t0x%08x\n",
				i,
				vcpu_arch->regs[i], vcpu_arch->regs[i+1],
				vcpu_arch->regs[i+2], vcpu_arch->regs[i+3]);
		i += 3;
	}
	printk(KERN_DEBUG "\n");
	printk(KERN_DEBUG "fiq regs:\t0x%08x\t0x%08x\t0x%08x\t0x%08x\n"
			  "         \t0x%08x\n",
			vcpu_arch->fiq_regs[0],
			vcpu_arch->fiq_regs[1],
			vcpu_arch->fiq_regs[2],
			vcpu_arch->fiq_regs[3],
			vcpu_arch->fiq_regs[4]);

	printk(KERN_DEBUG "\n");
	printk(KERN_DEBUG "cpsr: 0x%08x (mode: %s)\n", vcpu_arch->cpsr, mode);

	printk(KERN_DEBUG "\n");
	printk(KERN_DEBUG "Banked registers:  \tr13\t\tr14\t\tspsr\n");
	printk(KERN_DEBUG "             SVC:  \t0x%08x\t0x%08x\t0x%08x\n",
			vcpu_arch->banked_r13[MODE_SVC],
			vcpu_arch->banked_r14[MODE_SVC],
			vcpu_arch->banked_spsr[MODE_SVC]);
	printk(KERN_DEBUG "             ABT:  \t0x%08x\t0x%08x\t0x%08x\n",
			vcpu_arch->banked_r13[MODE_ABORT],
			vcpu_arch->banked_r14[MODE_ABORT],
			vcpu_arch->banked_spsr[MODE_ABORT]);
	printk(KERN_DEBUG "             UND:  \t0x%08x\t0x%08x\t0x%08x\n",
			vcpu_arch->banked_r13[MODE_UNDEF],
			vcpu_arch->banked_r14[MODE_UNDEF],
			vcpu_arch->banked_spsr[MODE_UNDEF]);
	printk(KERN_DEBUG "             IRQ:  \t0x%08x\t0x%08x\t0x%08x\n",
			vcpu_arch->banked_r13[MODE_IRQ],
			vcpu_arch->banked_r14[MODE_IRQ],
			vcpu_arch->banked_spsr[MODE_IRQ]);
	printk(KERN_DEBUG "             FIQ:  \t0x%08x\t0x%08x\t0x%08x\n",
			vcpu_arch->banked_r13[MODE_FIQ],
			vcpu_arch->banked_r14[MODE_FIQ],
			vcpu_arch->banked_spsr[MODE_FIQ]);


	printk(KERN_DEBUG "=================================================\n");
}

#endif /* __ARM_KVM_HOST_H__ */
