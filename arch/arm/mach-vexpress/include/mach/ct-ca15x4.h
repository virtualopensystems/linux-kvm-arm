#ifndef __MACH_CT_CA15X4_H
#define __MACH_CT_CA15X4_H

/*
 * Physical base addresses
 */
#define CT_CA15X4_MPIC		(0x2c000000)

#define A15_MPCORE_GIC_DIST	(CT_CA15X4_MPIC + 0x1000)
#define A15_MPCORE_GIC_CPU	(CT_CA15X4_MPIC + 0x2000)

#define CT_CA15X4_CLCDC		(0x2a100000)

/*
 * Interrupts.  Those in {} are for AMBA devices
 */
#define IRQ_CT_CA15X4_CLCDC	{ 76 }

extern struct ct_desc ct_ca15x4_desc;
#endif
