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

	.text
	.align	PAGE_SHIFT

__kvm_hyp_code_start:
	.globl __kvm_hyp_code_start

/********************************************************************
 * Flush per-VMID TLBs
 */

ENTRY(__kvm_tlb_flush_vmid)
	bx	lr
ENDPROC(__kvm_tlb_flush_vmid)

/********************************************************************
 * Flush TLBs and instruction caches of current CPU for all VMIDs
 */

ENTRY(__kvm_flush_vm_context)
	bx	lr
ENDPROC(__kvm_flush_vm_context)

/********************************************************************
 *  Hypervisor world-switch code
 */

ENTRY(__kvm_vcpu_run)
	bx	lr


/********************************************************************
 * Hypervisor exception vector and handlers
 */

	.align 5
__kvm_hyp_vector:
	.globl __kvm_hyp_vector
	nop

/*
 * The below lines makes sure the HYP mode code fits in a single page (the
 * assembler will bark at you if it doesn't). Please keep them together. If
 * you plan to restructure the code or increase its size over a page, you'll
 * have to fix the code in init_hyp_mode().
 */
__kvm_hyp_code_end:
	.globl	__kvm_hyp_code_end

	.org	__kvm_hyp_code_start + PAGE_SIZE
