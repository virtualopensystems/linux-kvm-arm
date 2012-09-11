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

#ifndef __ARM_KVM_H__
#define __ARM_KVM_H__

#include <asm/types.h>

#define __KVM_HAVE_GUEST_DEBUG
#define __KVM_HAVE_IRQ_LINE

#define KVM_REG_SIZE(id)						\
	(1U << (((id) & KVM_REG_SIZE_MASK) >> KVM_REG_SIZE_SHIFT))

/*
 * Modes used for short-hand mode determinition in the world-switch code and
 * in emulation code.
 *
 * Note: These indices do NOT correspond to the value of the CPSR mode bits!
 */
enum vcpu_mode {
	MODE_FIQ = 0,
	MODE_IRQ,
	MODE_SVC,
	MODE_ABT,
	MODE_UND,
	MODE_USR,
	MODE_SYS
};

struct kvm_regs {
	__u32 regs0_7[8];	/* Unbanked regs. (r0 - r7)	   */
	__u32 fiq_regs8_12[5];	/* Banked fiq regs. (r8 - r12)	   */
	__u32 usr_regs8_12[5];	/* Banked usr registers (r8 - r12) */
	__u32 reg13[6];		/* Banked r13, indexed by MODE_	   */
	__u32 reg14[6];		/* Banked r13, indexed by MODE_	   */
	__u32 reg15;
	__u32 cpsr;
	__u32 spsr[5];		/* Banked SPSR,  indexed by MODE_  */
};

/* Supported Processor Types */
#define KVM_ARM_TARGET_CORTEX_A15	(0xC0F)

struct kvm_vcpu_init {
	__u32 target;
	__u32 features[7];
};

struct kvm_sregs {
};

struct kvm_fpu {
};

struct kvm_guest_debug_arch {
};

struct kvm_debug_exit_arch {
};

struct kvm_sync_regs {
};

struct kvm_arch_memory_slot {
};

/* For KVM_VCPU_GET_REG_LIST. */
struct kvm_reg_list {
	__u64 n; /* number of regs */
	__u64 reg[0];
};

/* If you need to interpret the index values, here is the key: */
#define KVM_REG_ARM_COPROC_MASK		0x000000000FFF0000
#define KVM_REG_ARM_COPROC_SHIFT	16
#define KVM_REG_ARM_32_OPC2_MASK	0x0000000000000007
#define KVM_REG_ARM_32_OPC2_SHIFT	0
#define KVM_REG_ARM_OPC1_MASK		0x0000000000000078
#define KVM_REG_ARM_OPC1_SHIFT		3
#define KVM_REG_ARM_CRM_MASK		0x0000000000000780
#define KVM_REG_ARM_CRM_SHIFT		7
#define KVM_REG_ARM_32_CRN_MASK		0x0000000000007800
#define KVM_REG_ARM_32_CRN_SHIFT	11

/* KVM_IRQ_LINE irq field index values */
#define KVM_ARM_IRQ_TYPE_SHIFT		24
#define KVM_ARM_IRQ_TYPE_MASK		0xff
#define KVM_ARM_IRQ_VCPU_SHIFT		16
#define KVM_ARM_IRQ_VCPU_MASK		0xff
#define KVM_ARM_IRQ_NUM_SHIFT		0
#define KVM_ARM_IRQ_NUM_MASK		0xffff

/* irq_type field */
#define KVM_ARM_IRQ_TYPE_CPU		0
#define KVM_ARM_IRQ_TYPE_SPI		1
#define KVM_ARM_IRQ_TYPE_PPI		2

/* out-of-kernel GIC cpu interrupt injection irq_number field */
#define KVM_ARM_IRQ_CPU_IRQ		0
#define KVM_ARM_IRQ_CPU_FIQ		1

/* Highest supported SPI, from VGIC_NR_IRQS */
#define KVM_ARM_IRQ_GIC_MAX		127

#endif /* __ARM_KVM_H__ */
