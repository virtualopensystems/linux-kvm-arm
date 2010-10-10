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
#include "../kernel/entry-header.S"
#include <linux/sched.h>

@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@  INTERRUPT VECTOR PAGE COMES HERE
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@

/*
 * This macro will temporarily store lr and r0 to pc-relative storage,
 * copy spsr to r0 and then change to SVC mode. Following it will
 * spill the guest registers to the shared page so they can be directly
 * accessed by the host kernel afterwards.
 *
 * sp-4:		spsr_<exception mode>
 * sp-8:		lr_<exception mode>
 * sp-12:	r14_usr
 * ...		...
 * sp-68:	r0
 *
 * The value of r1 upon return will be the exception index
 */
.macro kvm_excp_handler excpIdx, correction=0
	str	lr, 1f
	str	r0, 2f				  @ temporarily store guest r0 in 2f
	mrs	r0, spsr
	msr	cpsr_c, #0xd3			  @ change to supervisor mode (I/F bits on)
	ldr	lr, 3f
	str	r0, [lr, #SHARED_GUEST_CPSR]      @ save guest cpsr (excp. mode spsr)
	ldr	r0, 1f				  @ read exception lr
	.if \correction
	sub	r0, r0, #\correction 		  @ correct offset
	.endif
	str	r0, [lr, #(SHARED_GUEST_REGS + 4*15)] @ store fault address

	/*
	 * If it's not an IRQ or FIQ chances are that some form of emulation is
	 * needed. It's better to pollute the data cache (even for those rare
	 * occasions when the intruction is not needed) than to create aliases
	 * in the L1 cache by accessing guest data from the host kernel.
	 */
	.if (\excpIdx < ARM_EXCEPTION_IRQ) && (\excpIdx != ARM_EXCEPTION_PREF_ABORT)
	ldr	r0, [r0]
	str	r0, [lr, #SHARED_GUEST_INSTR]
	.endif

	add	lr, lr, #SHARED_GUEST_REGS	  @ point lr to shared_page->guest_regs
	ldr	r0, 2f   			  @ restore guest r0
	stmia	lr, {r0-r14}^			  @ store user mode regs to shared page
	sub	lr, lr, #SHARED_GUEST_REGS	  @ restore lr to point to shared page
	mov	r0, #\excpIdx
	str	r0, [lr, #SHARED_EXCEPTION_IDX]   @ store exception index on shared page
	ldr	r1, [lr, #SHARED_RET_PTR]	  @ load return pointer into r0
	mov	pc, r1				  @ jump to __exception_return
1:	.word 0
2:	.word 0
3:	.word SHARED_PAGE_BASE
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
	str	lr, 1f
	ldr	lr, 3f
	add	lr, lr, #SHARED_GUEST_REGS	  @ point lr to shared_page->guest_regs
	stmia	lr, {r0-r14}^			  @ store user mode regs to shared page
	sub	lr, lr, #SHARED_GUEST_REGS	  @ restore lr to point to shared page
	mrs	r0, spsr
	str	r0, [lr, #SHARED_GUEST_CPSR]      @ save guest cpsr (excp. mode spsr)
	ldr	r0, 1f				  @ read exception lr
	sub	r0, r0, #4
	str	r0, [lr, #(SHARED_GUEST_REGS + 4*15)] @ store fault address
	ldr	r0, [r0]
	str	r0, [lr, #SHARED_GUEST_INSTR]
	mov	r0, #ARM_EXCEPTION_SOFTWARE
	str	r0, [lr, #SHARED_EXCEPTION_IDX]   @ store exception index on shared page
	ldr	r1, [lr, #SHARED_RET_PTR]	  @ load return pointer into r0
	mov	pc, r1				  @ jump to __exception_return
1:	.word 0
3:	.word SHARED_PAGE_BASE

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

.globl __shared_page_start
__shared_page_start:
__shared_sp:
	.word 0
__return_ptr:
	.word 0
__host_sp:
	.word 0

__exception_index:
	.word 0

__guest_registers:
	.rept 16
	.word 0
	.endr
__guest_CPSR:
	.word 0

__host_registers:
	.rept 16
	.word	0
	.endr
__host_CPSR:
	.word 0
__host_SPSR:
	.word 0

__host_ttbr:
	.word	0

__shadow_ttbr:
	.word	0

__guest_dac:
	.word	0

__guest_asid:
	.word	0

__host_dac:
	.word	0

__host_asid:
	.word	0

__guest_instr:
	.word	0

#define HOST_REGS(n)    (__host_registers + (n * 4))
#define HOST_CPSR	__host_CPSR
#define HOST_SPSR	__host_SPSR

#define GUEST_REGS(n)   (__guest_registers + (n * 4))
#define GUEST_CPSR	__guest_CPSR

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
	str	r1, HOST_CPSR
	str	r2, HOST_SPSR
	b	load_guest_cpsr @ Ensure correct IMB operation

	@ Load guest CPSR into SPSR
load_guest_cpsr:
	ldr	r1, GUEST_CPSR
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
	str	sp, __host_sp
	ldr	sp, __shared_sp

	@ Allow min. client access to the special KVM domain
set_dacr:
	mrc	p15, 0, r0, c3, c0, 0	@ get current dacr
	str	r0, __host_dac
	ldr	r1, __guest_dac
	orr	r0, r0, r1
	mcr	p15, 0, r0, c3, c0, 0	@ set with KVM domain set to min. client

#ifdef CONFIG_CPU_HAS_ASID
	ldr	r1, __guest_asid
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
	mrc	p15, 0, r0, c2, c0
	str	r0, __host_ttbr
	ldr	r0, __shadow_ttbr
	mov	r2, #0
	mcr	p15, 0, r2, c7, c5, 6		@ flush BTAC/BTB
	mcr	p15, 0, r2, c7, c10, 4		@ drain write buffer
	mcr	p15, 0, r0, c2, c0, 0		@ set TTB 0
#if defined(CONFIG_CPU_CACHE_VIVT) && !defined(CONFIG_CPU_CACHE_VIPT)
#ifdef HARVARD_CACHE
	mcr	p15, 0, r2, c7, c14, 0		@ D cache clean+invalidate
	mcr	p15, 0, r2, c7, c5, 0		@ I+BTB cache invalidate
#else
	mcr	p15, 0, r2, c7, c15, 0		@ Cache clean+invalidate
#endif
#endif

	@ TEMP: Clean caches
#ifdef HARVARD_CACHE
	mcr	p15, 0, r2, c7, c14, 0		@ D cache clean+invalidate
	mcr	p15, 0, r2, c7, c5, 0		@ I+BTB cache invalidate
#else
	mcr	p15, 0, r2, c7, c15, 0		@ Cache clean+invalidate
#endif

	mcr	p15, 0, r2, c8, c7, 0		@ invalidate I & D TLBs

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
	ldr	r1, __guest_dac
	mcr	p15, 0, r1, c3, c0, 0

	@ Load guest registers
	adr	r0, __guest_registers
	ldmia	r0, {r0-lr}^
	ldr	lr, GUEST_REGS(15)

	@ Jump to guest
	movs  pc, lr          @Do the branch, setting the new CPSR

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
	ldr	r1, __host_dac
	orr	r2, r2, r1
	mcr	p15, 0, r2, c3, c0

	@ Switch the page tables
	ldr	r1, __host_ttbr
	mov	r2, #0
	mcr	p15, 0, r2, c7, c5, 6		@ flush BTAC/BTB
	mcr	p15, 0, r2, c7, c10, 4		@ drain write buffer
	mcr	p15, 0, r1, c2, c0, 0		@ set TTB 0

#ifdef CONFIG_CPU_HAS_ASID
	ldr	r1, __host_asid
	mcr	p15, 0, r1, c13, c0, 1		@ set context ID
#endif
	mcr	p15, 0, r2, c8, c7, 0		@ invalidate I & D TLBs

	@ TEMP: Clean caches
#ifdef HARVARD_CACHE
	mcr	p15, 0, r2, c7, c14, 0		@ D cache clean+invalidate
	mcr	p15, 0, r2, c7, c5, 0		@ I+BTB cache invalidate
#else
	mcr	p15, 0, r2, c7, c15, 0		@ Cache clean+invalidate
#endif


	@ Load the host DACR for Domain Access Permissions
	ldr	r1, __host_dac
	mcr	p15, 0, r1, c3, c0, 0

	@ Restore SP
	ldr	sp, __host_sp

	@ Load VCPU pointer and exception index
	ldr	r1, HOST_REGS(0)

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
	mrc	p15, 0, r2, c5, c0, 0	@get the fault status register
	str	r2, [r1, #VCPU_HOST_FSR]	
#elif defined(CONFIG_CPU_32v6)
	mrc	p15, 0, r2, c5, c0, 1	@get the instr fault status register
	str	r2, [r1, #VCPU_HOST_IFSR]	
#endif

	@ Restore host registers
load_host_regs:
	mov	r3, r0
	ldr	r1, HOST_CPSR
	ldr	r2, HOST_SPSR
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
 *      0x0:   orig_r0         <--- r0 and sp
 */
	sub	sp, sp, #12
	stmia	sp, {r0 - r2}		@ Store host registers
	sub	sp, sp, #12
	adr	r1, irq_kernel_resume	@ Where to resume
	mrs	r2, cpsr		@ CPSR when w return
	stmia	sp, {r0 - r2}
	mov	r0, sp
	ldr	pc, __irq_svc_address
irq_kernel_resume:
	add	sp, sp, #12
	ldmia	sp, {r0 - r2}
	add	sp, sp, #12

return_to_ioctl:
	@ Return to kvm_vcpu_ioctl_run
	mov	pc, lr

__irq_svc_address:
	.word	0

.globl __shared_page_end
__shared_page_end:
	.word 0

.globl __copy_irq_svc_address
__copy_irq_svc_address:
	ldr	r0, =__irq_svc
	str	r0, __irq_svc_address
	mov	pc, lr
