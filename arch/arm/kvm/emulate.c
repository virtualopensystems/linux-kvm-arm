/*
 * Copyright (C) 2012 - Virtual Open Systems and Columbia University
 * Author: Christoffer Dall <c.dall@virtualopensystems.com>
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

#include <asm/kvm_emulate.h>

#define VCPU_NR_MODES 7
#define REG_OFFSET(_reg) \
	(offsetof(struct kvm_regs, _reg) / sizeof(u32))

#define USR_REG_OFFSET(_num) REG_OFFSET(usr_regs[_num])

static const unsigned long vcpu_reg_offsets[VCPU_NR_MODES][16] = {
	/* FIQ Registers */
	{
		USR_REG_OFFSET(0), USR_REG_OFFSET(1), USR_REG_OFFSET(2),
		USR_REG_OFFSET(3), USR_REG_OFFSET(4), USR_REG_OFFSET(5),
		USR_REG_OFFSET(6), USR_REG_OFFSET(7),
		REG_OFFSET(fiq_regs[0]), /* r8 */
		REG_OFFSET(fiq_regs[1]), /* r9 */
		REG_OFFSET(fiq_regs[2]), /* r10 */
		REG_OFFSET(fiq_regs[3]), /* r11 */
		REG_OFFSET(fiq_regs[4]), /* r12 */
		REG_OFFSET(fiq_regs[5]), /* r13 */
		REG_OFFSET(fiq_regs[6]), /* r14 */
		REG_OFFSET(pc)		 /* r15 */
	},

	/* IRQ Registers */
	{
		USR_REG_OFFSET(0), USR_REG_OFFSET(1), USR_REG_OFFSET(2),
		USR_REG_OFFSET(3), USR_REG_OFFSET(4), USR_REG_OFFSET(5),
		USR_REG_OFFSET(6), USR_REG_OFFSET(7), USR_REG_OFFSET(8),
		USR_REG_OFFSET(9), USR_REG_OFFSET(10), USR_REG_OFFSET(11),
		USR_REG_OFFSET(12),
		REG_OFFSET(irq_regs[0]), /* r13 */
		REG_OFFSET(irq_regs[1]), /* r14 */
		REG_OFFSET(pc)	         /* r15 */
	},

	/* SVC Registers */
	{
		USR_REG_OFFSET(0), USR_REG_OFFSET(1), USR_REG_OFFSET(2),
		USR_REG_OFFSET(3), USR_REG_OFFSET(4), USR_REG_OFFSET(5),
		USR_REG_OFFSET(6), USR_REG_OFFSET(7), USR_REG_OFFSET(8),
		USR_REG_OFFSET(9), USR_REG_OFFSET(10), USR_REG_OFFSET(11),
		USR_REG_OFFSET(12),
		REG_OFFSET(svc_regs[0]), /* r13 */
		REG_OFFSET(svc_regs[1]), /* r14 */
		REG_OFFSET(pc)		 /* r15 */
	},

	/* ABT Registers */
	{
		USR_REG_OFFSET(0), USR_REG_OFFSET(1), USR_REG_OFFSET(2),
		USR_REG_OFFSET(3), USR_REG_OFFSET(4), USR_REG_OFFSET(5),
		USR_REG_OFFSET(6), USR_REG_OFFSET(7), USR_REG_OFFSET(8),
		USR_REG_OFFSET(9), USR_REG_OFFSET(10), USR_REG_OFFSET(11),
		USR_REG_OFFSET(12),
		REG_OFFSET(abt_regs[0]), /* r13 */
		REG_OFFSET(abt_regs[1]), /* r14 */
		REG_OFFSET(pc)	         /* r15 */
	},

	/* UND Registers */
	{
		USR_REG_OFFSET(0), USR_REG_OFFSET(1), USR_REG_OFFSET(2),
		USR_REG_OFFSET(3), USR_REG_OFFSET(4), USR_REG_OFFSET(5),
		USR_REG_OFFSET(6), USR_REG_OFFSET(7), USR_REG_OFFSET(8),
		USR_REG_OFFSET(9), USR_REG_OFFSET(10), USR_REG_OFFSET(11),
		USR_REG_OFFSET(12),
		REG_OFFSET(und_regs[0]), /* r13 */
		REG_OFFSET(und_regs[1]), /* r14 */
		REG_OFFSET(pc)	         /* r15 */
	},

	/* USR Registers */
	{
		USR_REG_OFFSET(0), USR_REG_OFFSET(1), USR_REG_OFFSET(2),
		USR_REG_OFFSET(3), USR_REG_OFFSET(4), USR_REG_OFFSET(5),
		USR_REG_OFFSET(6), USR_REG_OFFSET(7), USR_REG_OFFSET(8),
		USR_REG_OFFSET(9), USR_REG_OFFSET(10), USR_REG_OFFSET(11),
		USR_REG_OFFSET(12),
		REG_OFFSET(usr_regs[13]), /* r13 */
		REG_OFFSET(usr_regs[14]), /* r14 */
		REG_OFFSET(pc)	          /* r15 */
	},

	/* SYS Registers */
	{
		USR_REG_OFFSET(0), USR_REG_OFFSET(1), USR_REG_OFFSET(2),
		USR_REG_OFFSET(3), USR_REG_OFFSET(4), USR_REG_OFFSET(5),
		USR_REG_OFFSET(6), USR_REG_OFFSET(7), USR_REG_OFFSET(8),
		USR_REG_OFFSET(9), USR_REG_OFFSET(10), USR_REG_OFFSET(11),
		USR_REG_OFFSET(12),
		REG_OFFSET(usr_regs[13]), /* r13 */
		REG_OFFSET(usr_regs[14]), /* r14 */
		REG_OFFSET(pc)	          /* r15 */
	},
};

/*
 * Modes used for short-hand mode determinition in the world-switch code and
 * in emulation code.
 *
 * Note: These indices do NOT correspond to the value of the CPSR mode bits!
 */
enum vcpu_mode {
	VCPU_FIQ_MODE = 0,
	VCPU_IRQ_MODE,
	VCPU_SVC_MODE,
	VCPU_ABT_MODE,
	VCPU_UND_MODE,
	VCPU_USR_MODE,
	VCPU_SYS_MODE
};

static const u8 modes_table[32] = {
	0xf, 0xf, 0xf, 0xf, 0xf, 0xf, 0xf, 0xf,
	0xf, 0xf, 0xf, 0xf, 0xf, 0xf, 0xf, 0xf,
	VCPU_USR_MODE,	/* 0x0 */
	VCPU_FIQ_MODE,	/* 0x1 */
	VCPU_IRQ_MODE,	/* 0x2 */
	VCPU_SVC_MODE,	/* 0x3 */
	0xf, 0xf, 0xf,
	VCPU_ABT_MODE,	/* 0x7 */
	0xf, 0xf, 0xf,
	VCPU_UND_MODE,	/* 0xb */
	0xf, 0xf, 0xf,
	VCPU_SYS_MODE	/* 0xf */
};

static enum vcpu_mode vcpu_mode(u32 cpsr)
{
	u8 mode = modes_table[cpsr & 0x1f];
	BUG_ON(mode == 0xf);
	return mode;
};

/*
 * Return a pointer to the register number valid in the specified mode of
 * the virtual CPU.
 */
u32 *vcpu_reg_mode(struct kvm_vcpu *vcpu, u8 reg_num, u32 cpsr)
{
	unsigned long mode = vcpu_mode(cpsr);
	u32 *reg_array = (u32 *)&vcpu->arch.regs;

	return reg_array + vcpu_reg_offsets[mode][reg_num];
}

/*
 * Return the SPSR for the specified mode of the virtual CPU.
 */
u32 *vcpu_spsr_mode(struct kvm_vcpu *vcpu, u32 cpsr)
{
	switch (vcpu_mode(cpsr)) {
	case VCPU_SVC_MODE:
		return &vcpu->arch.regs.svc_regs[2];
	case VCPU_ABT_MODE:
		return &vcpu->arch.regs.abt_regs[2];
	case VCPU_UND_MODE:
		return &vcpu->arch.regs.und_regs[2];
	case VCPU_IRQ_MODE:
		return &vcpu->arch.regs.irq_regs[2];
	case VCPU_FIQ_MODE:
		return &vcpu->arch.regs.fiq_regs[7];
	default:
		BUG();
	}
}
