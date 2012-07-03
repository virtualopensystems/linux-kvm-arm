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
#include <linux/const.h>
#include <asm/unified.h>
#include <asm/page.h>
#include <asm/asm-offsets.h>
#include <asm/kvm_asm.h>
#include <asm/kvm_arm.h>

#define VCPU_USR_REG(_reg_nr)	(VCPU_USR_REGS + (_reg_nr * 4))
#define VCPU_USR_SP		(VCPU_USR_REG(13))
#define VCPU_FIQ_REG(_reg_nr)	(VCPU_FIQ_REGS + (_reg_nr * 4))
#define VCPU_FIQ_SPSR		(VCPU_FIQ_REG(7))

	.text
	.align	PAGE_SHIFT

__kvm_hyp_code_start:
	.globl __kvm_hyp_code_start

@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@  Flush TLBs and instruction caches of current CPU for all VMIDs
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@

ENTRY(__kvm_flush_vm_context)
	hvc	#0			@ switch to hyp-mode

	mov	r0, #0			@ rn parameter for c15 flushes is SBZ
	mcr     p15, 4, r0, c8, c7, 4   @ Invalidate Non-secure Non-Hyp TLB
	mcr     p15, 0, r0, c7, c5, 0   @ Invalidate instruction caches
	dsb
	isb

	hvc	#0			@ switch back to svc-mode, see hyp_svc
	bx	lr
ENDPROC(__kvm_flush_vm_context)

@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@  Hypervisor world-switch code
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@

/* These are simply for the macros to work - value don't have meaning */
.equ usr, 0
.equ svc, 1
.equ abt, 2
.equ und, 3
.equ irq, 4
.equ fiq, 5

.macro store_mode_state base_reg, mode
	.if \mode == usr
	mrs	r2, SP_usr
	mov	r3, lr
	stmdb	\base_reg!, {r2, r3}
	.elseif \mode != fiq
	mrs	r2, SP_\mode
	mrs	r3, LR_\mode
	mrs	r4, SPSR_\mode
	stmdb	\base_reg!, {r2, r3, r4}
	.else
	mrs	r2, r8_fiq
	mrs	r3, r9_fiq
	mrs	r4, r10_fiq
	mrs	r5, r11_fiq
	mrs	r6, r12_fiq
	mrs	r7, SP_fiq
	mrs	r8, LR_fiq
	mrs	r9, SPSR_fiq
	stmdb	\base_reg!, {r2-r9}
	.endif
.endm

.macro load_mode_state base_reg, mode
	.if \mode == usr
	ldmia	\base_reg!, {r2, r3}
	msr	SP_usr, r2
	mov	lr, r3
	.elseif \mode != fiq
	ldmia	\base_reg!, {r2, r3, r4}
	msr	SP_\mode, r2
	msr	LR_\mode, r3
	msr	SPSR_\mode, r4
	.else
	ldmia	\base_reg!, {r2-r9}
	msr	r8_fiq, r2
	msr	r9_fiq, r3
	msr	r10_fiq, r4
	msr	r11_fiq, r5
	msr	r12_fiq, r6
	msr	SP_fiq, r7
	msr	LR_fiq, r8
	msr	SPSR_fiq, r9
	.endif
.endm

/* Reads cp15 registers from hardware and stores them in memory
 * @vcpu:   If 0, registers are written in-order to the stack,
 * 	    otherwise to the VCPU struct pointed to by vcpup
 * @vcpup:  Register pointing to VCPU struct
 */
.macro read_cp15_state vcpu=0, vcpup
	mrc	p15, 0, r2, c1, c0, 0	@ SCTLR
	mrc	p15, 0, r3, c1, c0, 2	@ CPACR
	mrc	p15, 0, r4, c2, c0, 2	@ TTBCR
	mrc	p15, 0, r5, c3, c0, 0	@ DACR
	mrrc	p15, 0, r6, r7, c2	@ TTBR 0
	mrrc	p15, 1, r8, r9, c2	@ TTBR 1
	mrc	p15, 0, r10, c10, c2, 0	@ PRRR
	mrc	p15, 0, r11, c10, c2, 1	@ NMRR

	.if \vcpu == 0
	push	{r2-r11}		@ Push CP15 registers
	.else
	str	r2, [\vcpup, #VCPU_SCTLR]
	str	r3, [\vcpup, #VCPU_CPACR]
	str	r4, [\vcpup, #VCPU_TTBCR]
	str	r5, [\vcpup, #VCPU_DACR]
	add	\vcpup, \vcpup, #VCPU_TTBR0
	strd	r6, r7, [\vcpup]
	add	\vcpup, \vcpup, #(VCPU_TTBR1 - VCPU_TTBR0)
	strd	r8, r9, [\vcpup]
	sub	\vcpup, \vcpup, #(VCPU_TTBR1)
	str	r10, [\vcpup, #VCPU_PRRR]
	str	r11, [\vcpup, #VCPU_NMRR]
	.endif

	mrc	p15, 0, r2, c13, c0, 1	@ CID
	mrc	p15, 0, r3, c13, c0, 2	@ TID_URW
	mrc	p15, 0, r4, c13, c0, 3	@ TID_URO
	mrc	p15, 0, r5, c13, c0, 4	@ TID_PRIV
	mrc	p15, 0, r6, c5, c0, 0	@ DFSR
	mrc	p15, 0, r7, c5, c0, 1	@ IFSR
	mrc	p15, 0, r8, c5, c1, 0	@ ADFSR
	mrc	p15, 0, r9, c5, c1, 1	@ AIFSR
	mrc	p15, 0, r10, c6, c0, 0	@ DFAR
	mrc	p15, 0, r11, c6, c0, 2	@ IFAR
	mrc	p15, 0, r12, c12, c0, 0	@ VBAR

	.if \vcpu == 0
	push	{r2-r12}		@ Push CP15 registers
	.else
	str	r2, [\vcpup, #VCPU_CID]
	str	r3, [\vcpup, #VCPU_TID_URW]
	str	r4, [\vcpup, #VCPU_TID_URO]
	str	r5, [\vcpup, #VCPU_TID_PRIV]
	str	r6, [\vcpup, #VCPU_DFSR]
	str	r7, [\vcpup, #VCPU_IFSR]
	str	r8, [\vcpup, #VCPU_ADFSR]
	str	r9, [\vcpup, #VCPU_AIFSR]
	str	r10, [\vcpup, #VCPU_DFAR]
	str	r11, [\vcpup, #VCPU_IFAR]
	str	r12, [\vcpup, #VCPU_VBAR]
	.endif
.endm

/* Reads cp15 registers from memory and writes them to hardware
 * @vcpu:   If 0, registers are read in-order from the stack,
 * 	    otherwise from the VCPU struct pointed to by vcpup
 * @vcpup:  Register pointing to VCPU struct
 */
.macro write_cp15_state vcpu=0, vcpup
	.if \vcpu == 0
	pop	{r2-r12}
	.else
	ldr	r2, [\vcpup, #VCPU_CID]
	ldr	r3, [\vcpup, #VCPU_TID_URW]
	ldr	r4, [\vcpup, #VCPU_TID_URO]
	ldr	r5, [\vcpup, #VCPU_TID_PRIV]
	ldr	r6, [\vcpup, #VCPU_DFSR]
	ldr	r7, [\vcpup, #VCPU_IFSR]
	ldr	r8, [\vcpup, #VCPU_ADFSR]
	ldr	r9, [\vcpup, #VCPU_AIFSR]
	ldr	r10, [\vcpup, #VCPU_DFAR]
	ldr	r11, [\vcpup, #VCPU_IFAR]
	ldr	r12, [\vcpup, #VCPU_VBAR]
	.endif

	mcr	p15, 0, r2, c13, c0, 1	@ CID
	mcr	p15, 0, r3, c13, c0, 2	@ TID_URW
	mcr	p15, 0, r4, c13, c0, 3	@ TID_URO
	mcr	p15, 0, r5, c13, c0, 4	@ TID_PRIV
	mcr	p15, 0, r6, c5, c0, 0	@ DFSR
	mcr	p15, 0, r7, c5, c0, 1	@ IFSR
	mcr	p15, 0, r8, c5, c1, 0	@ ADFSR
	mcr	p15, 0, r9, c5, c1, 1	@ AIFSR
	mcr	p15, 0, r10, c6, c0, 0	@ DFAR
	mcr	p15, 0, r11, c6, c0, 2	@ IFAR
	mcr	p15, 0, r12, c12, c0, 0	@ VBAR

	.if \vcpu == 0
	pop	{r2-r11}
	.else
	ldr	r2, [\vcpup, #VCPU_SCTLR]
	ldr	r3, [\vcpup, #VCPU_CPACR]
	ldr	r4, [\vcpup, #VCPU_TTBCR]
	ldr	r5, [\vcpup, #VCPU_DACR]
	add	\vcpup, \vcpup, #VCPU_TTBR0
	ldrd	r6, r7, [\vcpup]
	add	\vcpup, \vcpup, #(VCPU_TTBR1 - VCPU_TTBR0)
	ldrd	r8, r9, [\vcpup]
	sub	\vcpup, \vcpup, #(VCPU_TTBR1)
	ldr	r10, [\vcpup, #VCPU_PRRR]
	ldr	r11, [\vcpup, #VCPU_NMRR]
	.endif

	mcr	p15, 0, r2, c1, c0, 0	@ SCTLR
	mcr	p15, 0, r3, c1, c0, 2	@ CPACR
	mcr	p15, 0, r4, c2, c0, 2	@ TTBCR
	mcr	p15, 0, r5, c3, c0, 0	@ DACR
	mcrr	p15, 0, r6, r7, c2	@ TTBR 0
	mcrr	p15, 1, r8, r9, c2	@ TTBR 1
	mcr	p15, 0, r10, c10, c2, 0	@ PRRR
	mcr	p15, 0, r11, c10, c2, 1	@ NMRR
.endm

/* Configures the HSTR (Hyp System Trap Register) on entry/return
 * (hardware reset value is 0) */
.macro set_hstr entry
	mrc	p15, 4, r2, c1, c1, 3
	ldr	r3, =(HSTR_T(9) | HSTR_T(10) | HSTR_T(11) | HSTR_T(15))
	.if \entry == 1
	orr	r2, r2, r3		@ Trap CR{9,10,11,15}
	.else
	bic	r2, r2, r3		@ Don't trap any CRx accesses
	.endif
	mcr	p15, 4, r2, c1, c1, 3
.endm

/* Configures the HCPTR (Hyp Coprocessor Trap Register) on entry/return
 * (hardware reset value is 0) */
.macro set_hcptr entry
	mrc	p15, 4, r2, c1, c1, 2
	ldr	r3, =(HCPTR_TTA)
	.if \entry == 1
	orr	r2, r2, r3		@ Trap some coproc-accesses
	.else
	bic	r2, r2, r3		@ Don't trap any coproc- accesses
	.endif
	mcr	p15, 4, r2, c1, c1, 2
.endm

/* Enable/Disable: stage-2 trans., trap interrupts, trap wfi, trap smc */
.macro configure_hyp_role entry, vcpu_ptr
	mrc	p15, 4, r2, c1, c1, 0	@ HCR
	bic	r2, r2, #HCR_VIRT_EXCP_MASK
	ldr	r3, =HCR_GUEST_MASK
	.if \entry == 1
	orr	r2, r2, r3
	ldr	r3, [\vcpu_ptr, #VCPU_IRQ_LINES]
	orr	r2, r2, r3
	.else
	bic	r2, r2, r3
	.endif
	mcr	p15, 4, r2, c1, c1, 0
.endm

@ Arguments:
@  r0: pointer to vcpu struct
ENTRY(__kvm_vcpu_run)
	hvc	#0			@ switch to hyp-mode

	@ Now we're in Hyp-mode and lr_usr, spsr_hyp are on the stack
	mrs	r2, sp_usr
	push	{r2}			@ Push r13_usr
	push	{r4-r12}		@ Push r4-r12

	store_mode_state sp, svc
	store_mode_state sp, abt
	store_mode_state sp, und
	store_mode_state sp, irq
	store_mode_state sp, fiq

	@ Store hardware CP15 state and load guest state
	read_cp15_state
	write_cp15_state 1, r0

	push	{r0}			@ Push the VCPU pointer

	@ Configure Hyp-role
	configure_hyp_role 1, r0

	@ Trap coprocessor CRx accesses
	set_hstr 1
	set_hcptr 1

	@ Write configured ID register into MIDR alias
	ldr	r1, [r0, #VCPU_MIDR]
	mcr	p15, 4, r1, c0, c0, 0

	@ Write guest view of MPIDR into VMPIDR
	ldr	r1, [r0, #VCPU_MPIDR]
	mcr	p15, 4, r1, c0, c0, 5

	@ Load guest registers
	add	r0, r0, #(VCPU_USR_SP)
	load_mode_state r0, usr
	load_mode_state r0, svc
	load_mode_state r0, abt
	load_mode_state r0, und
	load_mode_state r0, irq
	load_mode_state r0, fiq

	@ Load return state (r0 now points to vcpu->arch.regs.pc)
	ldmia	r0, {r2, r3}
	msr	ELR_hyp, r2
	msr	SPSR_cxsf, r3

	@ Set up guest memory translation
	sub	r1, r0, #(VCPU_PC - VCPU_KVM)	@ r1 points to kvm struct
	ldr	r1, [r1]
	add	r1, r1, #KVM_VTTBR
	ldrd	r2, r3, [r1]
	mcrr	p15, 6, r2, r3, c2	@ Write VTTBR

	@ Load remaining registers and do the switch
	sub	r0, r0, #(VCPU_PC - VCPU_USR_REGS)
	ldmia	r0, {r0-r12}
	eret

__kvm_vcpu_return:
	@ Set VMID == 0
	mov	r2, #0
	mov	r3, #0
	mcrr	p15, 6, r2, r3, c2	@ Write VTTBR

	@ Store return state
	mrs	r2, ELR_hyp
	mrs	r3, spsr
	str	r2, [r1, #VCPU_PC]
	str	r3, [r1, #VCPU_CPSR]

	@ Store guest registers
	add	r1, r1, #(VCPU_FIQ_SPSR + 4)
	store_mode_state r1, fiq
	store_mode_state r1, irq
	store_mode_state r1, und
	store_mode_state r1, abt
	store_mode_state r1, svc
	store_mode_state r1, usr
	sub	r1, r1, #(VCPU_USR_REG(13))

	@ Don't trap coprocessor accesses for host kernel
	set_hstr 0
	set_hcptr 0

	@ Reset Hyp-role
	configure_hyp_role 0, r1

	@ Let host read hardware MIDR
	mrc	p15, 0, r2, c0, c0, 0
	mcr	p15, 4, r2, c0, c0, 0

	@ Back to hardware MPIDR
	mrc	p15, 0, r2, c0, c0, 5
	mcr	p15, 4, r2, c0, c0, 5

	@ Store guest CP15 state and restore host state
	read_cp15_state 1, r1
	write_cp15_state

	load_mode_state sp, fiq
	load_mode_state sp, irq
	load_mode_state sp, und
	load_mode_state sp, abt
	load_mode_state sp, svc

	pop	{r4-r12}		@ Pop r4-r12
	pop	{r2}			@ Pop r13_usr
	msr	sp_usr, r2

	ldr	r2, =(~PAGE_MASK)	@ Get svc-cpsr in case we need it for
	mov	r1, sp			@ the __irq_svc call
	tst	r1, r2
	subeq	r2, r1, #0x1000
	bicne	r2, r1, r2
	ldr	r2, [r2, #4]		@ r2 = svc_cpsr

	hvc	#0			@ switch back to svc-mode, see hyp_svc

	cmp	r0, #ARM_EXCEPTION_IRQ
	bxne	lr			@ return to IOCTL

	/*
	 * It's time to launch the kernel IRQ handler for IRQ exceptions. This
	 * requires some manipulation though.
	 *
	 *  - The easiest entry point to the host handler is __irq_svc.
	 *  - The __irq_svc expects to be called from SVC mode, which has been
	 *    switched to from vector_stub code in entry-armv.S. The __irq_svc
	 *    calls svc_entry which uses values stored in memory and pointed to
	 *    by r0 to return from handler. We allocate this memory on the
	 *    stack, which will contain these values:
	 *      0x8:   cpsr
	 *      0x4:   return_address
	 *      0x0:   r0
	 */
	adr	r1, irq_kernel_resume	@ Where to resume
	push	{r0 - r2}
	mov	r0, sp
	b	__irq_svc

irq_kernel_resume:
	pop	{r0}
	add	sp, sp, #8
	bx	lr			@ return to IOCTL

@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@  Hypervisor exception vector and handlers
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@

/*
 * The KVM/ARM Hypervisor ABI is defined as follows:
 *
 * Entry to Hyp mode from the host kernel will happen _only_ when an HVC
 * instruction is issued since all traps are disabled when running the host
 * kernel as per the Hyp-mode initialization at boot time.
 *
 * HVC instructions cause a trap to the vector page + offset 0x18 (see hyp_hvc
 * below) when the HVC instruction is called from SVC mode (i.e. a guest or the
 * host kernel) and they cause a trap to the vector page + offset 0xc when HVC
 * instructions are called from within Hyp-mode.
 *
 * Hyp-ABI: Switching from host kernel to Hyp-mode:
 *    Switching to Hyp mode is done through a simple HVC instructions. The
 *    exception vector code will check that the HVC comes from VMID==0 and if
 *    so will store the necessary state on the Hyp stack, which will look like
 *    this (growing downwards, see the hyp_hvc handler):
 *      ...
 *      stack_page + 4: spsr (Host-SVC cpsr)
 *      stack_page    : lr_usr
 *      --------------: stack bottom
 *
 * Hyp-ABI: Switching from Hyp-mode to host kernel SVC mode:
 *    When returning from Hyp mode to SVC mode, another HVC instruction is
 *    executed from Hyp mode, which is taken in the hyp_svc handler. The
 *    bottom of the Hyp is derived from the Hyp stack pointer (only a single
 *    page aligned stack is used per CPU) and the initial SVC registers are
 *    used to restore the host state.
 *
 *
 * Note that the above is used to execute code in Hyp-mode from a host-kernel
 * point of view, and is a different concept from performing a world-switch and
 * executing guest code SVC mode (with a VMID != 0).
 */

@ Handle undef, svc, pabt, or dabt by crashing with a user notice
.macro bad_exception exception_code, panic_str
	mrrc	p15, 6, r2, r3, c2	@ Read VTTBR
	lsr	r3, r3, #16
	ands	r3, r3, #0xff

	@ COND:neq means we're probably in the guest and we can try fetching
	@ the vcpu pointer and stuff off the stack and keep our fingers crossed
	beq	99f
	mov	r0, #\exception_code
	pop	{r1}			@ Load VCPU pointer
	.if \exception_code == ARM_EXCEPTION_DATA_ABORT
	mrc	p15, 4, r2, c5, c2, 0	@ HSR
	mrc	p15, 4, r3, c6, c0, 0	@ HDFAR
	str	r2, [r1, #VCPU_HSR]
	str	r3, [r1, #VCPU_HDFAR]
	.endif
	.if \exception_code == ARM_EXCEPTION_PREF_ABORT
	mrc	p15, 4, r2, c5, c2, 0	@ HSR
	mrc	p15, 4, r3, c6, c0, 2	@ HIFAR
	str	r2, [r1, #VCPU_HSR]
	str	r3, [r1, #VCPU_HIFAR]
	.endif
	mrs	r2, ELR_hyp
	str	r2, [r1, #VCPU_HYP_PC]
	b	__kvm_vcpu_return

	@ We were in the host already
99:	hvc	#0	@ switch to SVC mode
	ldr	r0, \panic_str
	mrs	r1, ELR_hyp
	b	panic

.endm

	.text

	.align 5
__kvm_hyp_vector:
	.globl __kvm_hyp_vector

	@ Hyp-mode exception vector
	W(b)	hyp_reset
	W(b)	hyp_undef
	W(b)	hyp_svc
	W(b)	hyp_pabt
	W(b)	hyp_dabt
	W(b)	hyp_hvc
	W(b)	hyp_irq
	W(b)	hyp_fiq

	.align
hyp_reset:
	b	hyp_reset

	.align
hyp_undef:
	bad_exception ARM_EXCEPTION_UNDEFINED, und_die_str

	.align
hyp_svc:
	@ Can only get here if HVC or SVC is called from Hyp, mode which means
	@ we want to change mode back to SVC mode.
	push	{r12}
	mov	r12, sp
	bic	r12, r12, #0x0ff
	bic	r12, r12, #0xf00
	ldr	lr, [r12, #4]
	msr	SPSR_csxf, lr
	ldr	lr, [r12]
	pop	{r12}
	eret

	.align
hyp_pabt:
	bad_exception ARM_EXCEPTION_PREF_ABORT, pabt_die_str

	.align
hyp_dabt:
	bad_exception ARM_EXCEPTION_DATA_ABORT, dabt_die_str

	.align
hyp_hvc:
	@ Getting here is either becuase of a trap from a guest or from calling
	@ HVC from the host kernel, which means "switch to Hyp mode".
	push	{r0, r1, r2}

	@ Check syndrome register
	mrc	p15, 4, r0, c5, c2, 0	@ HSR
	lsr	r1, r0, #HSR_EC_SHIFT
	cmp	r1, #HSR_EC_HVC
	bne	guest_trap		@ Not HVC instr.

	@ Let's check if the HVC came from VMID 0 and allow simple
	@ switch to Hyp mode
	mrrc    p15, 6, r1, r2, c2
	lsr     r2, r2, #16
	and     r2, r2, #0xff
	cmp     r2, #0
	bne	guest_trap		@ Guest called HVC

	@ Store lr_usr,spsr (svc cpsr) on bottom of stack
	mov	r1, sp
	bic	r1, r1, #0x0ff
	bic	r1, r1, #0xf00
	str	lr, [r1]
	mrs	lr, spsr
	str	lr, [r1, #4]

	pop	{r0, r1, r2}

	@ Return to caller in Hyp mode
	mrs	lr, ELR_hyp
	mov	pc, lr

guest_trap:
	ldr	r1, [sp, #12]		@ Load VCPU pointer
	str	r0, [r1, #VCPU_HSR]
	add	r1, r1, #VCPU_USR_REG(3)
	stmia	r1, {r3-r12}
	sub	r1, r1, #(VCPU_USR_REG(3) - VCPU_USR_REG(0))
	pop	{r3, r4, r5}
	add	sp, sp, #4		@ We loaded the VCPU pointer above
	stmia	r1, {r3, r4, r5}
	sub	r1, r1, #VCPU_USR_REG(0)

	@ Check if we need the fault information
	lsr	r2, r0, #HSR_EC_SHIFT
	cmp	r2, #HSR_EC_IABT
	beq	2f
	cmpne	r2, #HSR_EC_DABT
	bne	1f

	@ For non-valid data aborts, get the offending instr. PA
	lsr	r2, r0, #HSR_ISV_SHIFT
	ands	r2, r2, #1
	bne	2f
	mrs	r3, ELR_hyp
	mcr	p15, 0, r3, c7, c8, 0	@ VA to PA, ATS1CPR
	mrrc	p15, 0, r4, r5, c7	@ PAR
	add	r6, r1, #VCPU_PC_IPA
	strd	r4, r5, [r6]

	@ Check if we might have a wide thumb instruction spill-over
	ldr	r5, =0xfff
	bic	r4, r3, r5		@ clear page mask
	sub	r5, r5, #1		@ last 2-byte page bounday, 0xffe
	cmp	r4, r5
	bne	2f
	add	r4, r3, #2		@ _really_ unlikely!
	mcr	p15, 0, r4, c7, c8, 0	@ VA to PA, ATS1CPR
	mrrc	p15, 0, r4, r5, c7	@ PAR
	add	r6, r1, #VCPU_PC_IPA2
	strd	r4, r5, [r6]

2:	mrc	p15, 4, r2, c6, c0, 0	@ HDFAR
	mrc	p15, 4, r3, c6, c0, 2	@ HIFAR
	mrc	p15, 4, r4, c6, c0, 4	@ HPFAR
	add	r5, r1, #VCPU_HDFAR
	stmia	r5, {r2, r3, r4}

1:	mov	r0, #ARM_EXCEPTION_HVC
	b	__kvm_vcpu_return

	.align
hyp_irq:
	push	{r0}
	ldr	r0, [sp, #4]		@ Load VCPU pointer
	add	r0, r0, #(VCPU_USR_REG(1))
	stmia	r0, {r1-r12}
	pop	{r0, r1}		@ r1 == vcpu pointer
	str	r0, [r1, #VCPU_USR_REG(0)]

	mov	r0, #ARM_EXCEPTION_IRQ
	b	__kvm_vcpu_return

	.align
hyp_fiq:
	b	hyp_fiq

	.ltorg

und_die_str:
	.ascii	"unexpected undefined exception in Hyp mode at: %#08x"
pabt_die_str:
	.ascii	"unexpected prefetch abort in Hyp mode at: %#08x"
dabt_die_str:
	.ascii	"unexpected data abort in Hyp mode at: %#08x"

/*
 * The below lines makes sure the HYP mode code fits in a single page (the
 * assembler will bark at you if it doesn't). Please keep them together. If
 * you plan to restructure the code or increase its size over a page, you'll
 * have to fix the code in init_hyp_mode().
 */
__kvm_hyp_code_end:
	.globl	__kvm_hyp_code_end

	.org	__kvm_hyp_code_start + PAGE_SIZE
