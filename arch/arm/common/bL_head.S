/*
 * arch/arm/common/bL_head.S -- big.LITTLE kernel re-entry point
 *
 * Created by:  Nicolas Pitre, March 2012
 * Copyright:   (C) 2012  Linaro Limited
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 *
 * Refer to Documentation/arm/big.LITTLE/cluster-pm-race-avoidance.txt
 * for details of the synchronisation algorithms used here.
 */

#include <linux/linkage.h>
#include <asm/bL_entry.h>

#include "vlock.h"

.if BL_SYNC_CLUSTER_CPUS
.error "cpus must be the first member of struct bL_cluster_sync_struct"
.endif

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
	 * MMU is off so we need to get to various variables in a
	 * position independent way.
	 */
	adr	r5, 3f
	ldmia	r5, {r6, r7, r8, r11}
	add	r6, r5, r6			@ r6 = bL_entry_vectors
	ldr	r7, [r5, r7]			@ r7 = bL_power_up_setup_phys
	ldr	r8, [r5, r8]			@ r8 = bL_sync_phys
	add	r11, r5, r11			@ r11 = first_man_locks

	mov	r0, #BL_SYNC_CLUSTER_SIZE
	mla	r8, r0, r10, r8			@ r8 = bL_sync cluster base

	@ Signal that this CPU is coming UP:
	mov	r0, #CPU_COMING_UP
	mov	r5, #BL_SYNC_CPU_SIZE
	mla	r5, r9, r5, r8			@ r5 = bL_sync cpu address
	strb	r0, [r5]

	dsb

	@ At this point, the cluster cannot unexpectedly enter the GOING_DOWN
	@ state, because there is at least one active CPU (this CPU).

	mov	r0, #.Lvlock_size
	mla	r11, r0, r10, r11		@ r11 = cluster first man lock
	mov	r0, r11
	mov	r1, r9				@ cpu
	bl	vlock_trylock

	cmp	r0, #0				@ failed to get the lock?
	bne	cluster_setup_wait		@ wait for cluster setup if so

	ldrb	r0, [r8, #BL_SYNC_CLUSTER_CLUSTER]
	cmp	r0, #CLUSTER_UP			@ cluster already up?
	bne	cluster_setup			@ if not, set up the cluster

	@ Otherwise, release the first man lock and skip setup:
	mov	r0, r11
	bl	vlock_unlock
	b	cluster_setup_complete

cluster_setup:
	@ Signal that the cluster is being brought up:
	mov	r0, #INBOUND_COMING_UP
	strb	r0, [r8, #BL_SYNC_CLUSTER_INBOUND]

	dsb

	@ Any CPU trying to take the cluster into CLUSTER_GOING_DOWN from this
	@ point onwards will observe INBOUND_COMING_UP and abort.

	@ Wait for any previously-pending cluster teardown operations to abort
	@ or complete:
cluster_teardown_wait:
	ldrb	r0, [r8, #BL_SYNC_CLUSTER_CLUSTER]
	cmp	r0, #CLUSTER_GOING_DOWN
	bne	first_man_setup
	wfe
	b	cluster_teardown_wait

first_man_setup:
	@ If the outbound gave up before teardown started, skip cluster setup:

	cmp	r0, #CLUSTER_UP
	beq	cluster_setup_leave

	@ power_up_setup is now responsible for setting up the cluster:

	cmp	r7, #0
	mov	r0, #1		@ second (cluster) affinity level
	blxne	r7		@ Call power_up_setup if defined

	dsb
	mov	r0, #CLUSTER_UP
	strb	r0, [r8, #BL_SYNC_CLUSTER_CLUSTER]

cluster_setup_leave:
	@ Leave the cluster setup critical section:

	mov	r0, #INBOUND_NOT_COMING_UP
	strb	r0, [r8, #BL_SYNC_CLUSTER_INBOUND]
	dsb
	sev

	mov	r0, r11
	bl	vlock_unlock
	b	cluster_setup_complete

	@ In the contended case, non-first men wait here for cluster setup
	@ to complete:
cluster_setup_wait:
	ldrb	r0, [r8, #BL_SYNC_CLUSTER_CLUSTER]
	cmp	r0, #CLUSTER_UP
	wfene
	bne	cluster_setup_wait

cluster_setup_complete:
	@ If a platform-specific CPU setup hook is needed, it is
	@ called from here.

	cmp	r7, #0
	mov	r0, #0		@ first (CPU) affinity level
	blxne	r7		@ Call power_up_setup if defined

	@ Mark the CPU as up:

	dsb
	mov	r0, #CPU_UP
	strb	r0, [r5]
	dsb
	sev

bL_entry_gated:
	ldr	r5, [r6, r4, lsl #2]		@ r5 = CPU entry vector
	cmp	r5, #0
	wfeeq
	beq	bL_entry_gated
	pr_dbg	r4, "released\n"
	bx	r5

	.align	2

3:	.word	bL_entry_vectors - .
	.word	bL_power_up_setup_phys - 3b
	.word	bL_sync_phys - 3b
	.word	first_man_locks - 3b

ENDPROC(bL_entry_point)

	.bss

	@ Magic to size and align the first-man vlock structures
	@ so that each does not cross a 1KB boundary.
	@ We also must ensure that none of these shares a cacheline with
	@ any data which might be accessed through the cache.

	.equ	.Log2, 0
	.rept	11
		.if (1 << .Log2) < VLOCK_SIZE
			.equ .Log2, .Log2 + 1
		.endif
	.endr
	.if	.Log2 > 10
		.error "vlock struct is too large for guaranteed barrierless access ordering"
	.endif
	.equ	.Lvlock_size, 1 << .Log2

	@ The presence of two .align directives here is deliberate: we must
	@ align to whichever of the two boundaries is larger:
	.align	__CACHE_WRITEBACK_ORDER
	.align	.Log2
first_man_locks:
	.rept	BL_NR_CLUSTERS
	.space	.Lvlock_size
	.endr
	.size	first_man_locks, . - first_man_locks
	.type	first_man_locks, #object

	.align	__CACHE_WRITEBACK_ORDER

	.type	bL_entry_vectors, #object
ENTRY(bL_entry_vectors)
	.space	4 * BL_NR_CLUSTERS * BL_CPUS_PER_CLUSTER

	.type	bL_power_up_setup_phys, #object
ENTRY(bL_power_up_setup_phys)
	.space  4		@ set by bL_cluster_sync_init()
