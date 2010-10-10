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

#define MODE_FIQ     0
#define MODE_IRQ     1
#define MODE_SVC     2
#define MODE_ABORT   3
#define MODE_UNDEF   4
#define MODE_USER    5
#define MODE_SYSTEM  6


struct kvm_regs {
	__u32 regs0_7[8];	/* A register for each of the unbanked 
				   registers (R0 - R7)                        */
	__u32 fiq_regs8_12[5];	/* A register for each of the banked fiq 
				   registers (R8 - R12)                       */
	__u32 usr_regs8_12[5];	/* A register for each of the banked usr 
				   registers (R8 - R12)                       */
	__u32 reg13[6];		/* Register 13 for each of the banked modes, 
				   indexed by MODE_                           */
	__u32 reg14[6];		/* Register 14 for each of the banked modes, 
				   indexed by MODE_                           */
	__u32 reg15;		/* Register 15 */
	__u32 cpsr;
	__u32 spsr[5];		/* The SPSR for each mode, indexed by MODE_. 
				   user and system do not have one            */
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
