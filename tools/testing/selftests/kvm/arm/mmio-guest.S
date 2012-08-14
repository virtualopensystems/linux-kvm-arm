/*
 * mmio-guest.S - world's simplest VM os - purely MMIO test
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
#include "mmio_test.h"

/******************************************************************************
 * Test code
 */
ctl	.req	r12	@ control IO base address
lio	.req	r11	@ local IO
hio	.req	r10	@ host IO

/* assumes ctl == IO_CTL_BASE */
.macro ctl_ok
	mov	r0, #CTL_OK
	strb	r0, [ctl]
.endm

	.arm
	.text

	@ Get some basic addresses into registers
	ldr	ctl, =IO_CTL_BASE
	ldr	hio, =IO_DATA_BASE
	ldr	lio, =io_data

	@ Perform a simple load test
	ldr	r0, [hio]
	ldr	r1, [lio]
	cmp	r0, r1
	blne	fail
	bleq	ok

	@ Perform a simple write test
	ldr	r0, [lio]
	str	r0, [hio]

	@ Perform a load-multiple load test
	ldmia	hio, {r1, r2, r3}
	ldmia	lio, {r4, r5, r6}
	cmp	r1, r4
	cmpeq	r2, r5
	cmpeq	r3, r6
	blne	fail
	bleq	ok

	@ Program (VM) done, all test cases completed
	b	done

.macro ok_fail ok
	push	{r0}
	.if \ok == 1
	mov	r0, #CTL_OK
	.else
	mov	r0, #CTL_FAIL
	.endif
	strb	r0, [ctl]
	pop	{r0}
	bx	lr
.endm

ok:
	ok_fail	1
fail:
	ok_fail	0
done:
	mov	r0, #CTL_DONE
	strb	r0, [ctl]

err:
	mov	r0, #CTL_ERR
	strb	r0, [ctl]

/******************************************************************************
 * Test Data to transfer via MMIO
 */

	.data
io_data:
	.ascii IO_DATA
