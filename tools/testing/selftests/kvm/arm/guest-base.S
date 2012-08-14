/*
 * guest-base.S - world's simplest VM os
 * Copyright (C) 2012 Christoffer Dall <cdall@cs.columbia.edu>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.# 
 */
#include "io_common.h"

	.arm
	.section .start, "x"

start:
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
	ldr	r0, =0
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
