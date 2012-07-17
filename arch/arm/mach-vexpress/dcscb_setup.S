/*
 * arch/arm/include/asm/dcscb_setup.S
 *
 * Created by:  Dave Martin, 2012-06-22
 * Copyright:   (C) 2012  Linaro Limited
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */


#include <linux/linkage.h>
#include <asm/bL_entry.h>


#define SLAVE_SNOOPCTL_OFFSET	0
#define SNOOPCTL_SNOOP_ENABLE	(1 << 0)
#define SNOOPCTL_DVM_ENABLE	(1 << 1)

#define CCI_STATUS_OFFSET	0xc
#define STATUS_CHANGE_PENDING	(1 << 0)

#define CCI_SLAVE_OFFSET(n)	(0x1000 + 0x1000 * (n))

#define RTSM_CCI_PHYS_BASE	0x2c090000
#define RTSM_CCI_SLAVE_A15	3
#define RTSM_CCI_SLAVE_A7	4

#define RTSM_CCI_A15_OFFSET	CCI_SLAVE_OFFSET(RTSM_CCI_SLAVE_A15)
#define RTSM_CCI_A7_OFFSET	CCI_SLAVE_OFFSET(RTSM_CCI_SLAVE_A7)


ENTRY(dcscb_power_up_setup)

	cmp	r0, #0			@ check affinity level
	beq	2f

/*
 * Enable cluster-level coherency, in preparation for turning on the MMU.
 * The ACTLR SMP bit does not need to be set here, because cpu_resume()
 * already restores that.
 */

	mrc	p15, 0, r0, c0, c0, 5	@ MPIDR
	ubfx	r0, r0, #8, #4		@ cluster

	@ A15/A7 may not require explicit L2 invalidation on reset, dependent
	@ on hardware integration desicions.
	@ For now, this code assumes that L2 is either already invalidated, or
	@ invalidation is not required.

	ldr	r3, =RTSM_CCI_PHYS_BASE + RTSM_CCI_A15_OFFSET
	cmp	r0, #0		@ A15 cluster?
	addne	r3, r3, #RTSM_CCI_A7_OFFSET - RTSM_CCI_A15_OFFSET

	@ r3 now points to the correct CCI slave register block

	ldr	r0, [r3, #SLAVE_SNOOPCTL_OFFSET]
	orr	r0, r0, #SNOOPCTL_SNOOP_ENABLE | SNOOPCTL_DVM_ENABLE
	str	r0, [r3, #SLAVE_SNOOPCTL_OFFSET]	@ enable CCI snoops

	@ Wait for snoop control change to complete:

	ldr	r3, =RTSM_CCI_PHYS_BASE

	b	1f
0:	dsb
1:	ldr	r0, [r3, #CCI_STATUS_OFFSET]
	tst	r0, #STATUS_CHANGE_PENDING
	bne	0b

2:	@ Implementation-specific local CPU setup operations should go here,
	@ if any.  In this case, there is nothing to do.

	bx	lr
ENDPROC(dcscb_power_up_setup)
