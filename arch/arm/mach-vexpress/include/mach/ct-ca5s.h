#ifndef __MACH_CT_CA5S_H
#define __MACH_CT_CA5S_H

/*
 * Physical base addresses
 */
#define CT_CA5S_MPIC		(0x2c000000)
#define CT_CA5S_L2CC		(0x2c0f0000)

#define A5_MPCORE_SCU		(CT_CA5S_MPIC + 0x0000)
#define A5_MPCORE_GIC_CPU	(CT_CA5S_MPIC + 0x0100)
#define A5_MPCORE_TWD		(CT_CA5S_MPIC + 0x0600)
#define A5_MPCORE_GIC_DIST	(CT_CA5S_MPIC + 0x1000)

#define CT_CA5S_HDLCD		(0x2a110000)

/*
 * Interrupts.  Those in {} are for AMBA devices
 */
#define IRQ_CT_CA5S_HDLCDC	{ 117 }

extern struct ct_desc ct_ca5s_desc;

#endif
