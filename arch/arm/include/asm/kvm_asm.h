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

#ifndef __ARM_KVM_ASM_H__
#define __ARM_KVM_ASM_H__


/*
 * Modes used for short-hand mode determinition in the world-switch code and
 * in emulation code.
 * Note: These indices do NOT correspond to the value of the CPSR mode bits!
 */
#define MODE_FIQ     0
#define MODE_IRQ     1
#define MODE_SVC     2
#define MODE_ABORT   3
#define MODE_UNDEF   4
#define MODE_USER    5
#define MODE_SYSTEM  6


#define ARM_EXCEPTION_RESET	  0
#define ARM_EXCEPTION_UNDEFINED   1
#define ARM_EXCEPTION_SOFTWARE    2
#define ARM_EXCEPTION_PREF_ABORT  3
#define ARM_EXCEPTION_DATA_ABORT  4
#define ARM_EXCEPTION_IRQ	  5
#define ARM_EXCEPTION_FIQ	  6

#define RESUME_GUEST  0
#define RESUME_HOST   1

#define SHARED_PAGE_BASE 0xffff1000

/* CP15 defines */
#define CP15_CR_V_BIT		(1 << 13)

#endif /* __ARM_KVM_ASM_H__ */
