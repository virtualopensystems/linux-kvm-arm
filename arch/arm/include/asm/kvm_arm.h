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
 */

#ifndef __KVM_ARM_H__
#define __KVM_ARM_H__

#include <asm/types.h>

/* Hyp Configuration Register (HCR) bits */
#define HCR_TGE		(1 << 27)
#define HCR_TVM		(1 << 26)
#define HCR_TTLB	(1 << 25)
#define HCR_TPU		(1 << 24)
#define HCR_TPC		(1 << 23)
#define HCR_TSW		(1 << 22)
#define HCR_TAC		(1 << 21)
#define HCR_TIDCP	(1 << 20)
#define HCR_TSC		(1 << 19)
#define HCR_TID3	(1 << 18)
#define HCR_TID2	(1 << 17)
#define HCR_TID1	(1 << 16)
#define HCR_TID0	(1 << 15)
#define HCR_TWE		(1 << 14)
#define HCR_TWI		(1 << 13)
#define HCR_DC		(1 << 12)
#define HCR_BSU		(3 << 10)
#define HCR_FB		(1 << 9)
#define HCR_VA		(1 << 8)
#define HCR_VI		(1 << 7)
#define HCR_VF		(1 << 6)
#define HCR_AMO		(1 << 5)
#define HCR_IMO		(1 << 4)
#define HCR_FMO		(1 << 3)
#define HCR_PTW		(1 << 2)
#define HCR_SWIO	(1 << 1)
#define HCR_VM		1
#define HCR_GUEST_MASK (HCR_TSC | HCR_TWE | HCR_TWI | HCR_VM | HCR_AMO | \
			HCR_AMO | HCR_IMO | HCR_FMO | HCR_SWIO)

/* Hyp System Control Register (HSCTLR) bits */
#define HSCTLR_TE	(1 << 30)
#define HSCTLR_EE	(1 << 25)
#define HSCTLR_FI	(1 << 21)
#define HSCTLR_WXN	(1 << 19)
#define HSCTLR_I	(1 << 12)
#define HSCTLR_C	(1 << 2)
#define HSCTLR_A	(1 << 1)
#define HSCTLR_M	1
#define HSCTLR_MASK	(HSCTLR_M | HSCTLR_A | HSCTLR_C | HSCTLR_I | \
			 HSCTLR_WXN | HSCTLR_FI | HSCTLR_EE | HSCTLR_TE)

/* TTBCR and HTCR Registers bits */
#define TTBCR_EAE	(1 << 31)
#define TTBCR_IMP	(1 << 30)
#define TTBCR_SH1	(3 << 28)
#define TTBCR_ORGN1	(3 << 26)
#define TTBCR_IRGN1	(3 << 24)
#define TTBCR_EPD1	(1 << 23)
#define TTBCR_A1	(1 << 22)
#define TTBCR_T1SZ	(3 << 16)
#define TTBCR_SH0	(3 << 12)
#define TTBCR_ORGN0	(3 << 10)
#define TTBCR_IRGN0	(3 << 8)
#define TTBCR_EPD0	(1 << 7)
#define TTBCR_T0SZ	3
#define HTCR_MASK	(TTBCR_T0SZ | TTBCR_IRGN0 | TTBCR_ORGN0 | TTBCR_SH0)


/* Virtualization Translation Control Register (VTCR) bits */
#define VTCR_SH0	(3 << 12)
#define VTCR_ORGN0	(3 << 10)
#define VTCR_IRGN0	(3 << 8)
#define VTCR_SL0	(3 << 6)
#define VTCR_S		(1 << 4)
#define VTCR_T0SZ	3
#define VTCR_MASK	(VTCR_SH0 | VTCR_ORGN0 | VTCR_IRGN0 | VTCR_SL0 | \
			 VTCR_S | VTCR_T0SZ | VTCR_MASK)
#define VTCR_HTCR_SH	(VTCR_SH0 | VTCR_ORGN0 | VTCR_IRGN0)
#define VTCR_SL_L2	0		/* Starting-level: 2 */
#define VTCR_SL_L1	(1 << 6)	/* Starting-level: 1 */
#define VTCR_GUEST_SL	VTCR_SL_L1
#define VTCR_GUEST_T0SZ	0
#if VTCR_GUEST_SL == 0
#define VTTBR_X		(14 - VTCR_GUEST_T0SZ)
#else
#define VTTBR_X		(5 - VTCR_GUEST_T0SZ)
#endif


#endif /* __KVM_ARM_H__ */
