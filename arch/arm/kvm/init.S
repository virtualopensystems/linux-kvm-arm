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

#include <linux/linkage.h>
#include <asm/unified.h>
#include <asm/asm-offsets.h>
#include <asm/kvm_asm.h>
#include <asm/kvm_arm.h>

@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@  Hypervisor initialization
@    - should be called with:
@        r0 = Hypervisor pgd pointer
@        r1 = top of Hyp stack (kernel VA)
@        r2 = pointer to hyp vectors
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
	.text
        .pushsection    .hyp.idmap.text,"ax"
	.align 12
__kvm_hyp_init:
	.globl __kvm_hyp_init

	@ Hyp-mode exception vector
	W(b)	.
	W(b)	.
	W(b)	.
	W(b)	.
	W(b)	.
	W(b)	__do_hyp_init
	W(b)	.
	W(b)	.

__do_hyp_init:
	@ Set the sp to end of this page and push data for later use
ARM(	add	r12, pc, #(__kvm_init_sp - .)	)
ARM(	sub	r12, r12, #8			)
THUMB(	adr	r12, __kvm_init_sp		)
	mov	sp, r12
	push	{r1, r2}

	@ Set the HTTBR to point to the hypervisor PGD pointer passed to
	@ function and set the upper bits equal to the kernel PGD.
	mrrc	p15, 1, r1, r2, c2
	mcrr	p15, 4, r0, r2, c2

	@ Set the HTCR and VTCR to the same shareability and cacheability
	@ settings as the non-secure TTBCR and with T0SZ == 0.
	mrc	p15, 4, r0, c2, c0, 2	@ HTCR
	ldr	r12, =HTCR_MASK
	bic	r0, r0, r12
	mrc	p15, 0, r1, c2, c0, 2	@ TTBCR
	and	r1, r1, #(HTCR_MASK & ~TTBCR_T0SZ)
	orr	r0, r0, r1
	mcr	p15, 4, r0, c2, c0, 2	@ HTCR

	mrc	p15, 4, r1, c2, c1, 2	@ VTCR
	bic	r1, r1, #(VTCR_HTCR_SH | VTCR_SL0)
	bic	r0, r0, #(~VTCR_HTCR_SH)
	orr	r1, r0, r1
	orr	r1, r1, #(VTCR_SL_L1 | VTCR_GUEST_T0SZ)
	mcr	p15, 4, r1, c2, c1, 2	@ VTCR

	@ Use the same memory attributes for hyp. accesses as the kernel
	@ (copy MAIRx ro HMAIRx).
	mrc	p15, 0, r0, c10, c2, 0
	mcr	p15, 4, r0, c10, c2, 0
	mrc	p15, 0, r0, c10, c2, 1
	mcr	p15, 4, r0, c10, c2, 1

	@ Set the HSCTLR to:
	@  - ARM/THUMB exceptions: Kernel config (Thumb-2 kernel)
	@  - Endianness: Kernel config
	@  - Fast Interrupt Features: Kernel config
	@  - Write permission implies XN: disabled
	@  - Instruction cache: enabled
	@  - Data/Unified cache: enabled
	@  - Memory alignment checks: enabled
	@  - MMU: enabled (this code must be run from an identity mapping)
	mrc	p15, 4, r0, c1, c0, 0	@ HSCR
	ldr	r12, =HSCTLR_MASK
	bic	r0, r0, r12
	mrc	p15, 0, r1, c1, c0, 0	@ SCTLR
	ldr	r12, =(HSCTLR_EE | HSCTLR_FI)
	and	r1, r1, r12
 ARM(	ldr	r12, =(HSCTLR_M | HSCTLR_A | HSCTLR_I)			)
 THUMB(	ldr	r12, =(HSCTLR_M | HSCTLR_A | HSCTLR_I | HSCTLR_TE)	)
	orr	r1, r1, r12
	orr	r0, r0, r1
	isb
	mcr	p15, 4, r0, c1, c0, 0	@ HSCR
	isb

	@ Set stack pointer and return to the kernel
	pop	{r1, r2}
	mov	sp, r1

	@ Set HVBAR to point to the HYP vectors
	mcr	p15, 4, r2, c12, c0, 0	@ HVBAR

	eret

	.ltorg

	.align 12

	__kvm_init_sp:
	.globl __kvm_hyp_init_end
__kvm_hyp_init_end:

	.popsection
