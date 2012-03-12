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
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
	.text
	.arm
	.align 12
__kvm_hyp_init:
	.globl __kvm_hyp_init

	@ Hyp-mode exception vector
	nop
	nop
	nop
	nop
	nop
	b	__do_hyp_init
	nop
	nop

__do_hyp_init:
	@ Set the sp to end of this page and push data for later use
	mov	sp, pc
	bic	sp, sp, #0x0ff
	bic	sp, sp, #0xf00
	add	sp, sp, #0x1000
	push	{r0, r1, r2, r12}

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
	@  - ARM/THUMB exceptions: ARM
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
	ldr	r12, =(HSCTLR_M | HSCTLR_A | HSCTLR_I)
	orr	r1, r1, r12
	orr	r0, r0, r1
	isb
	mcr	p15, 4, r0, c1, c0, 0	@ HSCR
	isb

	@ Set stack pointer and return to the kernel
	pop	{r0, r1, r2, r12}
	mov	sp, r1
	eret

	.ltorg

	.align 12

	__kvm_init_sp:
	.globl __kvm_hyp_init_end
__kvm_hyp_init_end:
