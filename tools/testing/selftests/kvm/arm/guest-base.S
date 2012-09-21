/*
 * guest-base.S - world's simplest VM os
 * Copyright (C) 2012 Christoffer Dall <cdall@cs.columbia.edu>
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
#include "io_common.h"

	.arm
	.section .start, "x"

start:
	@ Set SCTLR.V
	mrc p15, 0, r1, c1, c0, 0
	orr r1, r1, #(1 << 13)
	mcr p15, 0, r1, c1, c0, 0

	@ Set up stack
	ldr	sp, =stacktop
	bl	test
	ldr	r1, =IO_CTL_EXIT
	strb	r0, [r1]

	.text

/* helpers */
.globl ok
ok:
	ldr	r1, =IO_CTL_STATUS
	mov	r0, #0
	strb	r0, [r1]
	mov	pc, lr

.globl fail
fail:
	ldr	r1, =IO_CTL_STATUS
	ldr	r0, =1
	strb	r0, [r1]
	mov	pc, lr

.globl putc
putc:
	ldr	r1, =IO_CTL_PRINT
	strb	r0, [r1]
	mov	pc, lr

.globl vm_exit
vm_exit:
	ldr	r1, =IO_CTL_STUB
	strb	r0, [r1]
	mov	pc, lr

.section .text.extable
	b	impossible
	b	undef
	b	svc
	b	prefetch_abort
	b	data_abort
	b	impossible
	b	irq
	b	fiq

impossible:
	ldr	r0, =impossible_msg
	b	abort

svc:
	ldr	r0, =svc_msg
	b	abort

prefetch_abort:
	ldr	r0, =prefetch_msg
	b	abort

data_abort:
	ldr	r0, =data_msg
	b	abort

irq:
	ldr	r0, =irq_msg
	b	abort

fiq:
	ldr	r0, =fiq_msg
	b	abort

undef:
	push	{r1,r2}
	ldr	r1, =skip_undef
	ldr	r1, [r1]
	cmp	r1, #0
	beq	1f
	ldr	r1, =undef_count
	ldr	r2, [r1]
	add	r2, r2, #1
	str	r2, [r1]
	pop	{r1,r2}
	movs	pc, lr
1:	
	ldr	r0, =undef_msg
	b	abort

abort:
	ldr	r1, =IO_CTL_PRINT
	mov	r2, r0
	ldrb	r0, [r0]
1:	
	strb	r0, [r1]
	ldrb	r0, [r2, #1]!
	cmp	r0, #0
	bne	1b
	ldr	r1, =IO_CTL_EXIT
	mov	r0, #99
	strb	r0, [r1]
	
.data
.globl skip_undef
skip_undef:
	.int	0
.globl undef_count
undef_count:
	.int	0
impossible_msg:
	.asciz	"Impossible exception!\n"
undef_msg:
	.asciz	"Undefined exception!\n"
svc_msg:
	.asciz	"SVC exception!\n"
prefetch_msg:
	.asciz	"Prefetch abort!\n"
data_msg:
	.asciz	"Data abort!\n"
irq_msg:
	.asciz	"IRQ exception!\n"
fiq_msg:
	.asciz	"FIQ exception!\n"
