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

#ifndef __ARM_KVM_H__
#define __ARM_KVM_H__

/* This is needed for QEMU to interact */
#define KVM_CAP_DESTROY_MEMORY_REGION_WORKS 21


#include <asm/types.h>


struct kvm_regs {
	__u32 regs0_7[8];	/* Unbanked regs. (r0 - r7)	   */
	__u32 fiq_regs8_12[5];	/* Banked fiq regs. (r8 - r12)	   */
	__u32 usr_regs8_12[5];	/* Banked usr registers (r8 - r12) */
	__u32 reg13[6];		/* Banked r13, indexed by MODE_	   */
	__u32 reg14[6];		/* Banked r13, indexed by MODE_	   */
	__u32 reg15;
	__u32 cpsr;
	__u32 spsr[5];		/* Banked SPSR,  indexed by MODE_  */
	struct {
		__u32 c0_cpuid;
		__u32 c2_base0;
		__u32 c2_base1;
		__u32 c3;
	} cp15;

};

struct kvm_sregs {
};

struct kvm_fpu {
};

/* for KVM_SET_GUEST_DEBUG */
struct kvm_guest_debug_arch {
	int enabled;
	unsigned long bp;
	int singlestep;
};

#endif /* __ARM_KVM_H__ */
