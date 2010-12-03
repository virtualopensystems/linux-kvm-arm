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
 * Authors: Christoffer Dall:  cd2436@columbia.edu
 *
 */
#include <asm/memory.h>
#include <asm/page.h>
#include <asm/asm-offsets.h>
#include <asm/kvm_asm.h>
#include <mach/vmalloc.h>
#include <linux/sched.h>

#ifdef CONFIG_CPU_V6
#define HARVARD_CACHE
#define HARVARD_TLB
#endif

@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@  INTERRUPT VECTOR PAGE COMES HERE
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@

#define VCPU_REGS_OFF(__var)	(SHARED_VCPU_REGS + VCPU_REGS_##__var)

/*
 * This macro will temporarily a corrected lr (address of exception-generating
 * instruction) and the spsr (guest execution cpsr) to the SVC mode stack.
 * Specifically, the SVC mode stack pointer must point to the last used
 * downward-growing stack on the shared page, so that the SRS instruction
 * can be used with the SVC r13 register as the base. Following the macro will
 * spill the guest registers to the shared page so they can be directly
 * accessed by the host kernel afterwards.
 *
 * The value of r0 upon return will be the exception index
 *
 * TODO: Consider re-ordering kvm_vcpu_regs so the SRS instruction stores the
 *	 pc and execution cpsr directly (would involve moving execution_cpsr
 *	 from shared_page to kvm_vcpu_regs.
 */
.macro kvm_excp_handler excpIdx, correction=0
	.if \correction
	sub	lr, lr, #\correction 		  @ correct offset
	.endif
	srsdb	#0x13		@ Store r14 and spsr on svc stack

	/*
	 * Change mode if not SWI (already in SVC mode)
	 */
	.if (\excpIdx != ARM_EXCEPTION_SOFTWARE)
	cpsid	if, #0x13
	.endif

	/*
	 * Store the guest register state to the shared page
	 */
	ldr	lr, [sp]	@ Load shared page base address
	add	lr, lr, #VCPU_REGS_OFF(SHARED_REG)
	stmia	lr, {r0-r7}^	@ Store shared r0-r7
	sub	lr, lr, #VCPU_REGS_OFF(SHARED_REG)	@ Point lr to shared
	ldr	r0, [lr, #SHARED_VCPU_MODE]
	add	lr, lr, #VCPU_REGS_OFF(FIQ)		@ Point lr to fiq_reg
	cmp	r0, #MODE_FIQ
	stmeqia	lr, {r8-r12}^		@ Store FIQ r8-r12
	add	lr, lr, #(5 << 2)	@ Point lr to usr_reg
	stmneia	lr, {r8-r12}^		@ Store USR r8-r12
	add	lr, lr, #(5 << 2)	@ Point lr to banked_fiq
	cmp	r0, #MODE_SYSTEM
	subeq	r0, r0, #1		@ SYSTEM -> USER (for r13-r14)
	add	lr, lr, r0, lsl #3	@ Jump to r13/r14 for GUEST_MODE
	stmia	lr, {r13,r14}^		@ Store r13/r14

	ldr	lr, [sp]		@ Load shared page base address
	ldmdb	sp, {r0, r1}		@ Load fault address and cpsr
	str	r0, [lr, #VCPU_REGS_OFF(R15)]		@ store fault address
	str	r1, [lr, #SHARED_EXEC_CPSR]

	/*
	 * If it's not an IRQ or FIQ chances are that some form of emulation is
	 * needed. It's better to pollute the data cache (even for those rare
	 * occasions when the intruction is not needed) than to create aliases
	 * in the L1 cache by accessing guest data from the host kernel.
	 */
	.if (\excpIdx < ARM_EXCEPTION_IRQ) && (\excpIdx != ARM_EXCEPTION_PREF_ABORT)
	ldr	r1, [r0]
	str	r1, [lr, #SHARED_GUEST_INSTR]
	.endif

	.if (\excpIdx == ARM_EXCEPTION_SOFTWARE)
	@ Get page-masked version of instruction address
	mov	r4, #0xf000
	sub	r4, r4, #1
	mvn	r4, r4		@ r4 = 0xfffff000 (PAGE_MASK)
	and	r3, r0, r4

	@ Save the instr after the SWI (if in same page)
	add	r1, r0, #4
	and	r2, r1, r4
	cmp	r2, r3
	movne	r1, #0
	ldreq	r1, [r1]
	str	r1, [lr, #SHARED_ORIG_INSTR]
	.endif

	/*
	 * Return exception index and begin journey back.
	 */
	mov	r0, #\excpIdx			  @ Return excp. index in r0
	ldr	r1, [lr, #SHARED_RET_PTR]	  @ load return pointer into r1
	mov	pc, r1				  @ jump to __exception_return
.endm

	.globl __irq_vector_start
__irq_vector_start:
@
@ The jump table to be used for interrupts when running guest
@
	.globl __guest_irq_vector
__guest_irq_vector:
	b __guest_reset_handler			@ reset exception
	b __guest_undefined_handler		@ undefined exception
	b __guest_swi_handler			@ swi exception
	b __guest_prefetch_abort_handler	@ prefetch arbort
	b __guest_data_abort_handler		@ data abort
	.word	0				@ RESERVED
	b __guest_irq_handler			@ irq
	b __guest_fiq_handler			@ fiq

	.globl __guest_reset_handler
__guest_reset_handler:
	kvm_excp_handler ARM_EXCEPTION_RESET

	.globl __guest_undefined_handler
__guest_undefined_handler:
	kvm_excp_handler ARM_EXCEPTION_UNDEFINED, 4

	.globl __guest_swi_handler
__guest_swi_handler:
	kvm_excp_handler ARM_EXCEPTION_SOFTWARE, 4


#if 0
	str	lr, 1f
	str	r0, 2f
	ldr	lr, 3f

	/*
	 * Store guest state and registers (not the PC) on the shared page
	 */
	mrs	r0, spsr
	str	r0, [lr, #SHARED_EXEC_CPSR]
	ldr	r0, [lr, #SHARED_VCPU_MODE]
	add	lr, lr, #VCPU_REGS_OFF(FIQ)	@ Point lr to fiq_reg
	cmp	r0, #MODE_FIQ
	stmeqia	lr, {r8-r12}^		@ Store FIQ r8-r12
	add	lr, lr, #(5 << 2)	@ Point lr to usr_reg
	stmneia	lr, {r8-r12}^		@ Store USR r8-r12
	add	lr, lr, #(5 << 2)	@ Point lr to banked_fiq
	cmp	r0, #MODE_SYSTEM
	subeq	r0, r0, #1		@ SYSTEM -> USER (for r13-r14)
	add	lr, lr, r0, lsl #3	@ Jump to r13/r14 for GUEST_MODE
	stmia	lr, {r13,r14}^		@ Store r13/r14
	sub	lr, lr, r0, lsl #3	@ Point lr to banked_fiq
	add	lr, lr, #(6 * (2 << 2)) @ Point lr to shared_reg
	ldr	r0, 2f   		@ Restore guest r0
	stmia	lr, {r0-r7}^		@ Store shared r0-r7
	sub	lr, lr, #VCPU_REGS_OFF(SHARED_REG)

	/*
	 * Store the guest PC (SWI instr. address) and the SWI instruction.
	 */
	ldr	r0, 1f				@ read exception lr
	sub	r0, r0, #4			@ Correction
	str	r0, [lr, #VCPU_REGS_OFF(R15)]	@ store fault address
	ldr	r5, [r0]
	str	r5, [lr, #SHARED_GUEST_INSTR]

	@ Get page-masked version of instruction address
	ldr	r4, 4f
	bic	r3, r0, r4

	@ Save the instr after the SWI (if in same page)
	add	r1, r0, #4
	bic	r2, r1, r4
	cmp	r2, r3
	movne	r1, #0
	ldreq	r1, [r1]
	str	r1, [lr, #SHARED_ORIG_INSTR]

	/*
	 * Return exception index and begin journey back.
	 */
	mov	r0, #ARM_EXCEPTION_SOFTWARE
	ldr	r1, [lr, #SHARED_RET_PTR]	  @ load return pointer into r0
	mov	pc, r1				  @ jump to __exception_return
1:	.word 0
2:	.word 0
3:	.word SHARED_PAGE_BASE
4:	.word 0xfff
#endif

	.globl __guest_prefetch_abort_handler
__guest_prefetch_abort_handler:
	kvm_excp_handler ARM_EXCEPTION_PREF_ABORT, 4

	.globl __guest_data_abort_handler
__guest_data_abort_handler:
	kvm_excp_handler ARM_EXCEPTION_DATA_ABORT, 8

	.globl __guest_irq_handler
__guest_irq_handler:
	kvm_excp_handler ARM_EXCEPTION_IRQ, 4

	.globl __guest_fiq_handler
__guest_fiq_handler:
	kvm_excp_handler ARM_EXCEPTION_FIQ, 4

	.globl __irq_vector_end
__irq_vector_end:
   .word 0

@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@  SHARED PAGE COMES HERE
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@

#define SHARED(__var)     (__shared_page_start + SHARED_##__var)
#define VCPU_REGS(__var)  (SHARED(VCPU_REGS) + VCPU_REGS_##__var)
#define HOST_REGS(n)      (SHARED(HOST_REGS) + (n * 4))

@ Clobbers reg
.macro flush_prefetch_dwb reg
	ldr	\reg, SHARED(FULL_FLUSH)
	cmp	\reg, #0
	mov	\reg, #0
	beq	10f

#ifdef HARVARD_CACHE
       mcr     p15, 0, \reg, c7, c14, 0  @ Clean + Invalidate entire D-cache
       mcr     p15, 0, \reg, c7, c5,  0  @ Invalidate entire I-cache
#else
       mcr     p15, 0, \reg, c7, c15, 0  @ Clean + Invalidate unified cache
#endif

	mcr	p15, 0, \reg, c8, c6, 0  @ Flush D-TLB
	mcr	p15, 0, \reg, c8, c5, 0  @ Flush I-TLB
	mcr	p15, 0, \reg, c7, c5, 6  @ Flush branch target cache

10:
	mcr	p15, 0, \reg, c7, c5,  4	@ Flush Prefetch Buffer
	mcr	p15, 0, \reg, c7, c10, 4	@ Data Synchronization Barrier
.endm

.globl __shared_page_start
__shared_page_start:

/*
 * Make space for all the required fields in the shared page here by simply
 * reserving the number of bytes that the shared_page struct takes up.
 */
.space SIZEOF_SHARED_STRUCT

@Arguments:
@ r0: will point to vcpu struct
.globl __vcpu_run
__vcpu_run:
	@ Store host registers
	str	r0, HOST_REGS(0)
	str	r1, HOST_REGS(1)
	adr	r1, HOST_REGS(2)
	stmia	r1, {r2-r14}
	mrs	r1, cpsr
	mrs	r2, spsr
	str	r1, SHARED(HOST_CPSR)
	str	r2, SHARED(HOST_SPSR)
	b	load_guest_cpsr @ Ensure correct IMB operation

	@ Load guest CPSR into SPSR
load_guest_cpsr:
	ldr	r1, SHARED(EXEC_CPSR)
	msr	spsr_cxsf, r1
	mrs	r1, spsr

	@ Set interrupt vector location
	ldr	r1, [r0, #VCPU_HOST_VEC_HIGH]
	mrc	p15, 0, r2, c1, c0, 0
	cmp	r1, #0
	orrne	r2, #CP15_CR_V_BIT
	andeq	r2, #~CP15_CR_V_BIT
	mcr	p15, 0, r2, c1, c0, 0

	@ Set SP valid for shared page
	str	sp, SHARED(HOST_SP)
	ldr	sp, SHARED(SHARED_SP)

	@ Allow min. client access to the special KVM domain
set_dacr:
	mrc	p15, 0, r0, c3, c0, 0	@ get current dacr
	str	r0, SHARED(HOST_DAC)
	ldr	r1, SHARED(GUEST_DAC)
	orr	r0, r0, r1
	mcr	p15, 0, r0, c3, c0, 0	@ set with KVM domain set to min. client

#ifdef CONFIG_CPU_HAS_ASID
	ldr	r1, SHARED(GUEST_ASID)
	mcr	p15, 0, r1, c13, c0, 1		@ set context ID
#endif

	@ Set the XP-bit
	/*
	 * TODO: If the guest has MMU enabled but XP bit set to 0
	 * we need to also set the XP bit to 0. If the MMU is disabled
	 * we use VMSAv6 subpages disabled for page tables and should
	 * set the XP bit to 1.
	 *
	 * For now, we assume the XP bit is simply 1.
	 */
	@ Switch the page tables
	mrc	p15, 0, r0, c2, c0	@ Load Host TTBR
	str	r0, SHARED(HOST_TTBR)
	ldr	r0, SHARED(SHADOW_TTBR)
	mcr	p15, 0, r0, c2, c0, 0	@ Set TTBR0 for shadow page table

	@ Invalidate and clean all caches and TLB entries
	flush_prefetch_dwb r2

#if 0
	@ Invalidate the kernel global TLB mappings
	@ldr	r1, __task_size
	mov	r1, #TASK_SIZE  @ TODO: Check this is shift, not data access!!!!
1:	mcr	p15, 0, r1, c8, c7, 1
	mcr	p15, 0, r1, c8, c6, 1		@ TLB invalidate D MVA (was 1)
	mcrne	p15, 0, r1, c8, c5, 1		@ TLB invalidate I MVA (was 1)
	adds	r1, r1, #(1<<12)
	bcs	1b
	*/
#endif

	@ Load the guest DACR for Domain Access Permissions
	ldr	r1, SHARED(GUEST_DAC)
	mcr	p15, 0, r1, c3, c0, 0

	@ Load guest registers
	ldr	r1, SHARED(VCPU_MODE)
	adr	lr, VCPU_REGS(FIQ)
	cmp	r1, #MODE_FIQ
	ldmeqia	lr, {r8-r12}^			@ Load FIQ r8-r12
	adr	lr, VCPU_REGS(USR)
	ldmneia	lr, {r8-r12}^			@ Load USR r8-r12
	adr	lr, VCPU_REGS(BANKED_FIQ)
	cmp	r1, #MODE_SYSTEM
	subeq	r1, r1, #1			@ SYSTEM -> USER (for r13-r14)
	add	lr, r1, lsl #3			@ Jump to r13/r14 for vcpu mode
	ldmia	lr, {r13, r14}^
	adr	lr, VCPU_REGS(SHARED_REG)
	ldmia	lr, {r0-r7}^			@ Load remaining shared r0-r7
	ldr	lr, VCPU_REGS(R15)		@ Load the guest PC in r14
	movs	pc, lr				@ Jump to guest!

	@ Large constants
__task_size:
	.word TASK_SIZE


/*
 * This code will get called from an exception handler in SVC mode.
 * Input:
 *   r0: exception index
 */
.globl __exception_return
__exception_return:
	@ Make sure the domain allows the host page table access to this page
	mrc	p15, 0, r2, c3, c0	@ get current dacr
	ldr	r1, SHARED(HOST_DAC)
	orr	r2, r2, r1
	mcr	p15, 0, r2, c3, c0


	@ Switch the page tables
	ldr	r1, SHARED(HOST_TTBR)
	mcr	p15, 0, r1, c2, c0, 0	@ set TTB 0

	@ Load VCPU pointer
	ldr	r1, HOST_REGS(0)

#ifdef CONFIG_CPU_HAS_ASID
	ldr	r2, SHARED(HOST_ASID)
	mcr	p15, 0, r2, c13, c0, 1		@ set context ID
#endif

	@ Invalidate and clean all caches and TLB entries
	flush_prefetch_dwb r2

	@ Load the host DACR for Domain Access Permissions
	ldr	r2, SHARED(HOST_DAC)
	mcr	p15, 0, r2, c3, c0, 0

	@ Restore SP
	ldr	sp, SHARED(HOST_SP)

	@ Set interrupt vector back to high vectors
#if CONFIG_VECTORS_BASE == 0xffff0000
	mrc	p15, 0, r2, c1, c0, 0
	orr	r2, #CP15_CR_V_BIT
	mcr	p15, 0, r2, c1, c0, 0
#endif

	@ Save CR, FAR and FSR on abort exceptions
check_aborts:
	cmp	r0, #ARM_EXCEPTION_DATA_ABORT
	beq	save_data_far_fsr
	cmp	r0, #ARM_EXCEPTION_PREF_ABORT
	beq	save_instr_far_fsr
	b	load_host_regs
save_data_far_fsr:
	mrc	p15, 0, r2, c5, c0, 0	@get the fault status register
	str	r2, [r1, #VCPU_HOST_FSR]
	mrc	p15, 0, r2, c6, c0, 0	@get the fault address register
	str	r2, [r1, #VCPU_HOST_FAR]
	b	load_host_regs
save_instr_far_fsr:
#if defined(CONFIG_CPU_32v5)
	mrc	p15, 0, r2, c5, c0, 1	@get the instr fault status register
	str	r2, [r1, #VCPU_HOST_IFSR]
#elif defined(CONFIG_CPU_32v6)
	mrc	p15, 0, r2, c5, c0, 1	@get the instr fault status register
	str	r2, [r1, #VCPU_HOST_IFSR]
#endif

	@ Restore host registers
load_host_regs:
	mov	r3, r0
	ldr	r1, SHARED(HOST_CPSR)
	ldr	r2, SHARED(HOST_SPSR)
	msr	cpsr_csxf, r1
	msr	spsr_cxsf, r2
	adr	r1, HOST_REGS(1)
	ldmia	r1, {r1-r14}

	@ Load exception index in r0 and check if exception was IRQ
	cmp	r0, #ARM_EXCEPTION_IRQ
	bne	return_to_ioctl

/*
 * It's time to launch the kernel IRQ handler for IRQ exceptions. This
 * requires some manipulation though.
 *
 * ARMv5 / ARMv6:
 *  - The easiest entry point to the host handler is __irq_svc. The address
 *    to this code has already been loaded into __irq_svc_address by
 *    kvm_arch_vcpu_create().
 *  - The __irq_svc expects to be called from SVC mode, which has been
 *    switched to from vector_stub code in entry-armv.S. The __irq_svc calls
 *    svc_entry which uses values stored in memory and pointed to by r0
 *    to return from handler. We allocate this memory on the stack, which
 *    will contain these values:
 *      0x8:   cpsr
 *      0x4:   return_address
 *      0x0:   orig_r0		<--- r0 and sp
 */
	sub	sp, sp, #12
	stmia	sp, {r0 - r2}		@ Store host registers
	sub	sp, sp, #12
	adr	r1, irq_kernel_resume	@ Where to resume
	mrs	r2, cpsr		@ CPSR when w return
	stmia	sp, {r0 - r2}
	mov	r0, sp
	ldr	pc, SHARED(IRQ_SVC_ADDR)
irq_kernel_resume:
	add	sp, sp, #12
	ldmia	sp, {r0 - r2}
	add	sp, sp, #12

return_to_ioctl:
	@ Return to kvm_vcpu_ioctl_run
	mov	pc, lr

.globl __shared_page_end
__shared_page_end:
	.word 0
