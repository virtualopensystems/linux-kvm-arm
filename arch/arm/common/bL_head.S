/*
 * arch/arm/common/bL_head.S -- big.LITTLE kernel re-entry point
 *
 * Created by:  Nicolas Pitre, March 2012
 * Copyright:   (C) 2012  Linaro Limited
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/linkage.h>
#include <asm/bL_entry.h>

	.macro	pr_dbg	cpu, string
#if defined(CONFIG_DEBUG_LL) && defined(DEBUG)
	b	1901f
1902:	.ascii	"CPU 0: \0CPU 1: \0CPU 2: \0CPU 3: \0"
	.ascii	"CPU 4: \0CPU 5: \0CPU 6: \0CPU 7: \0"
1903:	.asciz	"\string"
	.align
1901:	adr	r0, 1902b
	add	r0, r0, \cpu, lsl #3
	bl	printascii
	adr	r0, 1903b
	bl	printascii
#endif
	.endm

	.arm
	.align

ENTRY(bL_entry_point)

 THUMB(	adr	r12, BSYM(1f)	)
 THUMB(	bx	r12		)
 THUMB(	.thumb			)
1:
	mrc	p15, 0, r0, c0, c0, 5
	ubfx	r9, r0, #0, #4			@ r9 = cpu
	ubfx	r10, r0, #8, #4			@ r10 = cluster
	mov	r3, #BL_CPUS_PER_CLUSTER
	mla	r4, r3, r10, r9			@ r4 = canonical CPU index
	cmp	r4, #(BL_CPUS_PER_CLUSTER * BL_NR_CLUSTERS)
	blo	2f

	/* We didn't expect this CPU.  Try to make it quiet. */
1:	wfi
	wfe
	b	1b

2:	pr_dbg	r4, "kernel bL_entry_point\n"

	/*
	 * MMU is off so we need to get to bL_entry_vectors in a
	 * position independent way.
	 */
	adr	r5, 3f
	ldr	r6, [r5]
	add	r6, r5, r6			@ r6 = bL_entry_vectors

bL_entry_gated:
	ldr	r5, [r6, r4, lsl #2]		@ r5 = CPU entry vector
	cmp	r5, #0
	wfeeq
	beq	bL_entry_gated
	pr_dbg	r4, "released\n"
	bx	r5

	.align	2

3:	.word	bL_entry_vectors - .

ENDPROC(bL_entry_point)

	.bss
	.align	5

	.type	bL_entry_vectors, #object
ENTRY(bL_entry_vectors)
	.space	4 * BL_NR_CLUSTERS * BL_CPUS_PER_CLUSTER
