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
#include <asm/ptrace.h>
#include <asm/asm-offsets.h>
#include <asm/kvm_asm.h>
#include <asm/kvm_arm.h>
#include <asm/vfpmacros.h>
#include "interrupts_head.S"

	.text
	.align	PAGE_SHIFT

__kvm_hyp_code_start:
	.globl __kvm_hyp_code_start

/********************************************************************
 * Flush per-VMID TLBs
 *
 * void __kvm_tlb_flush_vmid(struct kvm *kvm);
 *
 * We rely on the hardware to broadcast the TLB invalidation to all CPUs
 * inside the inner-shareable domain (which is the case for all v7
 * implementations).  If we come across a non-IS SMP implementation, we'll
 * have to use an IPI based mechanism. Until then, we stick to the simple
 * hardware assisted version.
 */
ENTRY(__kvm_tlb_flush_vmid)
	push	{r2, r3}

	add	r0, r0, #KVM_VTTBR
	ldrd	r2, r3, [r0]
	mcrr	p15, 6, r2, r3, c2	@ Write VTTBR
	isb
	mcr     p15, 0, r0, c8, c3, 0	@ TLBIALLIS (rt ignored)
	dsb
	isb
	mov	r2, #0
	mov	r3, #0
	mcrr	p15, 6, r2, r3, c2	@ Back to VMID #0
	isb				@ Not necessary if followed by eret

	pop	{r2, r3}
	bx	lr
ENDPROC(__kvm_tlb_flush_vmid)

/********************************************************************
 * Flush TLBs and instruction caches of current CPU for all VMIDs
 *
 * void __kvm_flush_vm_context(void);
 */
ENTRY(__kvm_flush_vm_context)
	mov	r0, #0			@ rn parameter for c15 flushes is SBZ
	mcr     p15, 4, r0, c8, c7, 4   @ Invalidate Non-secure Non-Hyp TLB
	mcr     p15, 0, r0, c7, c5, 0   @ Invalidate instruction caches
	dsb
	isb				@ Not necessary if followed by eret

	bx	lr
ENDPROC(__kvm_flush_vm_context)


/********************************************************************
 *  Hypervisor world-switch code
 *
 *
 * int __kvm_vcpu_run(struct kvm_vcpu *vcpu)
 */
ENTRY(__kvm_vcpu_run)
	@ Save the vcpu pointer
	mcr	p15, 4, r0, c13, c0, 2	@ HTPIDR

	save_host_regs

	restore_vgic_state r0
	restore_timer_state r0

	@ Store hardware CP15 state and load guest state
	read_cp15_state
	write_cp15_state 1, r0

	@ If the host kernel has not been configured with VFPv3 support,
	@ then it is safer if we deny guests from using it as well.
#ifdef CONFIG_VFPv3
	@ Set FPEXC_EN so the guest doesn't trap floating point instructions
	VFPFMRX r2, FPEXC		@ VMRS
	push	{r2}
	orr	r2, r2, #FPEXC_EN
	VFPFMXR FPEXC, r2		@ VMSR
#endif

	@ Configure Hyp-role
	configure_hyp_role 1, r0

	@ Trap coprocessor CRx accesses
	set_hstr 1
	set_hcptr 1, (HCPTR_TTA | HCPTR_TCP(10) | HCPTR_TCP(11))
	set_hdcr 1

	@ Write configured ID register into MIDR alias
	ldr	r1, [r0, #VCPU_MIDR]
	mcr	p15, 4, r1, c0, c0, 0

	@ Write guest view of MPIDR into VMPIDR
	ldr	r1, [r0, #CP15_OFFSET(c0_MPIDR)]
	mcr	p15, 4, r1, c0, c0, 5

	@ Set up guest memory translation
	ldr	r1, [r0, #VCPU_KVM]
	add	r1, r1, #KVM_VTTBR
	ldrd	r2, r3, [r1]
	mcrr	p15, 6, r2, r3, c2	@ Write VTTBR

	@ At this point, r0 must contain the pointer to the VCPU
	restore_guest_regs
	clrex				@ Clear exclusive monitor
	eret

__kvm_vcpu_return:
	/*
	 * return convention:
	 * vcpu r0, r1, r2 saved on the stack
	 * r0: exception code
	 * r1: vcpu pointer
	 */
	save_guest_regs

	@ Set VMID == 0
	mov	r2, #0
	mov	r3, #0
	mcrr	p15, 6, r2, r3, c2	@ Write VTTBR

	@ Don't trap coprocessor accesses for host kernel
	set_hstr 0
	set_hdcr 0
	set_hcptr 0, (HCPTR_TTA | HCPTR_TCP(10) | HCPTR_TCP(11))

#ifdef CONFIG_VFPv3
	@ Save floating point registers we if let guest use them.
	tst	r2, #(HCPTR_TCP(10) | HCPTR_TCP(11))
	bne	after_vfp_restore

	@ Switch VFP/NEON hardware state to the host's
	add	r7, r1, #VCPU_VFP_GUEST
	store_vfp_state r7
	add	r7, r1, #VCPU_VFP_HOST
	ldr	r7, [r7]
	restore_vfp_state r7

after_vfp_restore:
	@ Restore FPEXC_EN which we clobbered on entry
	pop	{r2}
	VFPFMXR FPEXC, r2
#endif

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

	save_timer_state r1
	save_vgic_state	r1

	restore_host_regs
	clrex				@ Clear exclusive monitor
	bx	lr			@ return to IOCTL

/********************************************************************
 * Translate VA to PA
 *
 * u64 __kvm_va_to_pa(struct kvm_vcpu *vcpu, u32 va, bool priv)
 *
 * Arguments:
 *  r0: pointer to vcpu struct
 *  r1: virtual address to map (rounded to page)
 *  r2: 1 = P1 (read) mapping, 0 = P0 (read) mapping.
 * Returns 64 bit PAR value.
 */
ENTRY(__kvm_va_to_pa)
	push	{r4-r12}

	@ Fold flag into r1, easier than using stack.
	cmp	r2, #0
	movne	r2, #1
	orr	r1, r1, r2

	@ This swaps too many registers, but we're in the slow path anyway.
	read_cp15_state
	write_cp15_state 1, r0

	ands	r2, r1, #1
	bic	r1, r1, r2
	mcrne	p15, 0, r1, c7, c8, 0	@ VA to PA, ATS1CPR
	mcreq	p15, 0, r1, c7, c8, 2	@ VA to PA, ATS1CUR
	isb

	@ Restore host state.
	read_cp15_state 1, r0
	write_cp15_state

	mrrc	p15, 0, r0, r1, c7	@ PAR
	pop	{r4-r12}
	bx	lr

ENTRY(kvm_call_hyp)
	hvc	#0
	bx	lr


/********************************************************************
 * Hypervisor exception vector and handlers
 *
 *
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
 * Hyp-ABI: Calling HYP-mode functions from host (in SVC mode):
 *    Switching to Hyp mode is done through a simple HVC #0 instruction. The
 *    exception vector code will check that the HVC comes from VMID==0 and if
 *    so will push the necessary state (SPSR, lr_usr) on the Hyp stack.
 *    - r0 contains a pointer to a HYP function
 *    - r1, r2, and r3 contain arguments to the above function.
 *    - The HYP function will be called with its arguments in r0, r1 and r2.
 *    On HYP function return, we return directly to SVC.
 *
 * Note that the above is used to execute code in Hyp-mode from a host-kernel
 * point of view, and is a different concept from performing a world-switch and
 * executing guest code SVC mode (with a VMID != 0).
 */

/* Handle undef, svc, pabt, or dabt by crashing with a user notice */
.macro bad_exception exception_code, panic_str
	push	{r0-r2}
	mrrc	p15, 6, r0, r1, c2	@ Read VTTBR
	lsr	r1, r1, #16
	ands	r1, r1, #0xff
	beq	99f

	load_vcpu	r1		@ Load VCPU pointer
	.if \exception_code == ARM_EXCEPTION_DATA_ABORT
	mrc	p15, 4, r2, c5, c2, 0	@ HSR
	mrc	p15, 4, r0, c6, c0, 0	@ HDFAR
	str	r2, [r1, #VCPU_HSR]
	str	r0, [r1, #VCPU_HxFAR]
	.endif
	.if \exception_code == ARM_EXCEPTION_PREF_ABORT
	mrc	p15, 4, r2, c5, c2, 0	@ HSR
	mrc	p15, 4, r0, c6, c0, 2	@ HIFAR
	str	r2, [r1, #VCPU_HSR]
	str	r0, [r1, #VCPU_HxFAR]
	.endif
	mov	r0, #\exception_code
	b	__kvm_vcpu_return

	@ We were in the host already. Let's craft a panic-ing return to SVC.
99:	mrs	r2, cpsr
	bic	r2, r2, #MODE_MASK
	orr	r2, r2, #SVC_MODE
THUMB(	orr	r2, r2, #PSR_T_BIT	)
	msr	spsr_cxsf, r2
	mrs	r1, ELR_hyp
	ldr	r2, =BSYM(panic)
	msr	ELR_hyp, r2
	ldr	r0, \panic_str
	eret
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
	bad_exception ARM_EXCEPTION_HVC, svc_die_str

	.align
hyp_pabt:
	bad_exception ARM_EXCEPTION_PREF_ABORT, pabt_die_str

	.align
hyp_dabt:
	bad_exception ARM_EXCEPTION_DATA_ABORT, dabt_die_str

	.align
hyp_hvc:
	/*
	 * Getting here is either becuase of a trap from a guest or from calling
	 * HVC from the host kernel, which means "switch to Hyp mode".
	 */
	push	{r0, r1, r2}

	@ Check syndrome register
	mrc	p15, 4, r0, c5, c2, 0	@ HSR
	lsr	r1, r0, #HSR_EC_SHIFT
#ifdef CONFIG_VFPv3
	cmp	r1, #HSR_EC_CP_0_13
	beq	switch_to_guest_vfp
#endif
	cmp	r1, #HSR_EC_HVC
	bne	guest_trap		@ Not HVC instr.

	/*
	 * Let's check if the HVC came from VMID 0 and allow simple
	 * switch to Hyp mode
	 */
	mrrc    p15, 6, r1, r2, c2
	lsr     r2, r2, #16
	and     r2, r2, #0xff
	cmp     r2, #0
	bne	guest_trap		@ Guest called HVC

host_switch_to_hyp:
	pop	{r0, r1, r2}

	push	{lr}
	mrs	lr, SPSR
	push	{lr}

	mov	lr, r0
	mov	r0, r1
	mov	r1, r2
	mov	r2, r3

THUMB(	orr	lr, #1)
	blx	lr			@ Call the HYP function

	pop	{lr}
	msr	SPSR_csxf, lr
	pop	{lr}
	eret

guest_trap:
	load_vcpu	r1		@ Load VCPU pointer
	str	r0, [r1, #VCPU_HSR]

	@ Check if we need the fault information
	lsr	r0, r0, #HSR_EC_SHIFT
	cmp	r0, #HSR_EC_IABT
	mrceq	p15, 4, r2, c6, c0, 2	@ HIFAR
	beq	2f
	cmp	r0, #HSR_EC_DABT
	bne	1f
	mrc	p15, 4, r2, c6, c0, 0	@ HDFAR

2:	str	r2, [r1, #VCPU_HxFAR]
	mrc	p15, 4, r2, c6, c0, 4	@ HPFAR
	str	r2, [r1, #VCPU_HPFAR]

1:	mov	r0, #ARM_EXCEPTION_HVC
	b	__kvm_vcpu_return

/*
 * If VFPv3 support is not available, then we will not switch the VFP
 * registers; however cp10 and cp11 accesses will still trap and fallback
 * to the regular coprocessor emulation code, which currently will
 * inject an undefined exception to the guest.
 */
#ifdef CONFIG_VFPv3
switch_to_guest_vfp:
	load_vcpu	r0		@ Load VCPU pointer
	push	{r3-r7}

	@ NEON/VFP used.  Turn on VFP access.
	set_hcptr 0, (HCPTR_TCP(10) | HCPTR_TCP(11))

	@ Switch VFP/NEON hardware state to the guest's
	add	r7, r0, #VCPU_VFP_HOST
	ldr	r7, [r7]
	store_vfp_state r7
	add	r7, r0, #VCPU_VFP_GUEST
	restore_vfp_state r7

	pop	{r3-r7}
	pop	{r0-r2}
	eret
#endif

	.align
hyp_irq:
	push	{r0, r1, r2}
	mov	r0, #ARM_EXCEPTION_IRQ
	load_vcpu	r1		@ Load VCPU pointer
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
svc_die_str:
	.ascii	"unexpected HVC/SVC trap in Hyp mode at: %#08x"

/*
 * The below lines makes sure the HYP mode code fits in a single page (the
 * assembler will bark at you if it doesn't). Please keep them together. If
 * you plan to restructure the code or increase its size over a page, you'll
 * have to fix the code in init_hyp_mode().
 */
__kvm_hyp_code_end:
	.globl	__kvm_hyp_code_end

	.org	__kvm_hyp_code_start + PAGE_SIZE
