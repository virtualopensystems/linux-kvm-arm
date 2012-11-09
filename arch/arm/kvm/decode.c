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
#include <linux/kvm_host.h>
#include <asm/kvm_mmio.h>
#include <asm/kvm_emulate.h>
#include <asm/kvm_decode.h>
#include <trace/events/kvm.h>

#include "trace.h"

struct arm_instr {
	/* Instruction decoding */
	u32 opc;
	u32 opc_mask;

	/* Decoding for the register write back */
	bool register_form;
	u32 imm;
	u8 Rm;
	u8 type;
	u8 shift_n;

	/* Common decoding */
	u8 len;
	bool sign_extend;
	bool w;

	bool (*decode)(struct kvm_decode *decode, struct kvm_exit_mmio *mmio,
		       unsigned long instr, struct arm_instr *ai);
};

enum SRType {
	SRType_LSL,
	SRType_LSR,
	SRType_ASR,
	SRType_ROR,
	SRType_RRX
};

/* Modelled after DecodeImmShift() in the ARM ARM */
static enum SRType decode_imm_shift(u8 type, u8 imm5, u8 *amount)
{
	switch (type) {
	case 0x0:
		*amount = imm5;
		return SRType_LSL;
	case 0x1:
		*amount = (imm5 == 0) ? 32 : imm5;
		return SRType_LSR;
	case 0x2:
		*amount = (imm5 == 0) ? 32 : imm5;
		return SRType_ASR;
	case 0x3:
		if (imm5 == 0) {
			*amount = 1;
			return SRType_RRX;
		} else {
			*amount = imm5;
			return SRType_ROR;
		}
	}

	return SRType_LSL;
}

/* Modelled after Shift() in the ARM ARM */
static u32 shift(u32 value, u8 N, enum SRType type, u8 amount, bool carry_in)
{
	u32 mask = (1 << N) - 1;
	s32 svalue = (s32)value;

	BUG_ON(N > 32);
	BUG_ON(type == SRType_RRX && amount != 1);
	BUG_ON(amount > N);

	if (amount == 0)
		return value;

	switch (type) {
	case SRType_LSL:
		value <<= amount;
		break;
	case SRType_LSR:
		 value >>= amount;
		break;
	case SRType_ASR:
		if (value & (1 << (N - 1)))
			svalue |= ((-1UL) << N);
		value = svalue >> amount;
		break;
	case SRType_ROR:
		value = (value >> amount) | (value << (N - amount));
		break;
	case SRType_RRX: {
		u32 C = (carry_in) ? 1 : 0;
		value = (value >> 1) | (C << (N - 1));
		break;
	}
	}

	return value & mask;
}

static bool decode_arm_wb(struct kvm_decode *decode, struct kvm_exit_mmio *mmio,
			  unsigned long instr, const struct arm_instr *ai)
{
	u8 Rt = (instr >> 12) & 0xf;
	u8 Rn = (instr >> 16) & 0xf;
	u8 W = (instr >> 21) & 1;
	u8 U = (instr >> 23) & 1;
	u8 P = (instr >> 24) & 1;
	u32 base_addr = *kvm_decode_reg(decode, Rn);
	u32 offset_addr, offset;

	/*
	 * Technically this is allowed in certain circumstances,
	 * but we don't support it.
	 */
	if (Rt == 15 || Rn == 15)
		return false;

	if (P && !W) {
		kvm_err("Decoding operation with valid ISV?\n");
		return false;
	}

	decode->rt = Rt;

	if (ai->register_form) {
		/* Register operation */
		enum SRType s_type;
		u8 shift_n = 0;
		bool c_bit = *kvm_decode_cpsr(decode) & PSR_C_BIT;
		u32 s_reg = *kvm_decode_reg(decode, ai->Rm);

		s_type = decode_imm_shift(ai->type, ai->shift_n, &shift_n);
		offset = shift(s_reg, 5, s_type, shift_n, c_bit);
	} else {
		/* Immediate operation */
		offset = ai->imm;
	}

	/* Handle Writeback */
	if (U)
		offset_addr = base_addr + offset;
	else
		offset_addr = base_addr - offset;
	*kvm_decode_reg(decode, Rn) = offset_addr;
	return true;
}

static bool decode_arm_ls(struct kvm_decode *decode, struct kvm_exit_mmio *mmio,
			  unsigned long instr, struct arm_instr *ai)
{
	u8 A = (instr >> 25) & 1;

	mmio->is_write = ai->w;
	mmio->len = ai->len;
	decode->sign_extend = false;

	ai->register_form = A;
	ai->imm = instr & 0xfff;
	ai->Rm = instr & 0xf;
	ai->type = (instr >> 5) & 0x3;
	ai->shift_n = (instr >> 7) & 0x1f;

	return decode_arm_wb(decode, mmio, instr, ai);
}

static bool decode_arm_extra(struct kvm_decode *decode,
			     struct kvm_exit_mmio *mmio,
			     unsigned long instr, struct arm_instr *ai)
{
	mmio->is_write = ai->w;
	mmio->len = ai->len;
	decode->sign_extend = ai->sign_extend;

	ai->register_form = !((instr >> 22) & 1);
	ai->imm = ((instr >> 4) & 0xf0) | (instr & 0xf);
	ai->Rm = instr & 0xf;
	ai->type = 0; /* SRType_LSL */
	ai->shift_n = 0;

	return decode_arm_wb(decode, mmio, instr, ai);
}

/*
 * The encodings in this table assumes that a fault was generated where the
 * ISV field in the HSR was clear, and the decoding information was invalid,
 * which means that a register write-back occurred, the PC was used as the
 * destination or a load/store multiple operation was used. Since the latter
 * two cases are crazy for MMIO on the guest side, we simply inject a fault
 * when this happens and support the common case.
 *
 * We treat unpriviledged loads and stores of words and bytes like all other
 * loads and stores as their encodings mandate the W bit set and the P bit
 * clear.
 */
static const struct arm_instr arm_instr[] = {
	/**************** Load/Store Word and Byte **********************/
	/* Store word with writeback */
	{ .opc = 0x04000000, .opc_mask = 0x0c500000, .len = 4, .w = true,
		.sign_extend = false, .decode = decode_arm_ls },
	/* Store byte with writeback */
	{ .opc = 0x04400000, .opc_mask = 0x0c500000, .len = 1, .w = true,
		.sign_extend = false, .decode = decode_arm_ls },
	/* Load word with writeback */
	{ .opc = 0x04100000, .opc_mask = 0x0c500000, .len = 4, .w = false,
		.sign_extend = false, .decode = decode_arm_ls },
	/* Load byte with writeback */
	{ .opc = 0x04500000, .opc_mask = 0x0c500000, .len = 1, .w = false,
		.sign_extend = false, .decode = decode_arm_ls },

	/*************** Extra load/store instructions ******************/

	/* Store halfword with writeback */
	{ .opc = 0x000000b0, .opc_mask = 0x0c1000f0, .len = 2, .w = true,
		.sign_extend = false, .decode = decode_arm_extra },
	/* Load halfword with writeback */
	{ .opc = 0x001000b0, .opc_mask = 0x0c1000f0, .len = 2, .w = false,
		.sign_extend = false, .decode = decode_arm_extra },

	/* Load dual with writeback */
	{ .opc = 0x000000d0, .opc_mask = 0x0c1000f0, .len = 8, .w = false,
		.sign_extend = false, .decode = decode_arm_extra },
	/* Load signed byte with writeback */
	{ .opc = 0x001000d0, .opc_mask = 0x0c1000f0, .len = 1, .w = false,
		.sign_extend = true,  .decode = decode_arm_extra },

	/* Store dual with writeback */
	{ .opc = 0x000000f0, .opc_mask = 0x0c1000f0, .len = 8, .w = true,
		.sign_extend = false, .decode = decode_arm_extra },
	/* Load signed halfword with writeback */
	{ .opc = 0x001000f0, .opc_mask = 0x0c1000f0, .len = 2, .w = false,
		.sign_extend = true,  .decode = decode_arm_extra },

	/* Store halfword unprivileged */
	{ .opc = 0x002000b0, .opc_mask = 0x0f3000f0, .len = 2, .w = true,
		.sign_extend = false, .decode = decode_arm_extra },
	/* Load halfword unprivileged */
	{ .opc = 0x003000b0, .opc_mask = 0x0f3000f0, .len = 2, .w = false,
		.sign_extend = false, .decode = decode_arm_extra },
	/* Load signed byte unprivileged */
	{ .opc = 0x003000d0, .opc_mask = 0x0f3000f0, .len = 1, .w = false,
		.sign_extend = true , .decode = decode_arm_extra },
	/* Load signed halfword unprivileged */
	{ .opc = 0x003000d0, .opc_mask = 0x0f3000f0, .len = 2, .w = false,
		.sign_extend = true , .decode = decode_arm_extra },
};

static bool kvm_decode_arm_ls(struct kvm_decode *decode, unsigned long instr,
			      struct kvm_exit_mmio *mmio)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(arm_instr); i++) {
		const struct arm_instr *ai = &arm_instr[i];
		if ((instr & ai->opc_mask) == ai->opc) {
			struct arm_instr ai_copy = *ai;
			return ai->decode(decode, mmio, instr, &ai_copy);
		}
	}
	return false;
}

struct thumb_instr {
	bool is32;

	u8 opcode;
	u8 opcode_mask;
	u8 op2;
	u8 op2_mask;

	bool (*decode)(struct kvm_decode *decode, struct kvm_exit_mmio *mmio,
		       unsigned long instr, const struct thumb_instr *ti);
};

static bool decode_thumb_wb(struct kvm_decode *decode,
			    struct kvm_exit_mmio *mmio,
			    unsigned long instr)
{
	bool P = (instr >> 10) & 1;
	bool U = (instr >> 9) & 1;
	u8 imm8 = instr & 0xff;
	u32 offset_addr = decode->fault_addr;
	u8 Rn = (instr >> 16) & 0xf;

	decode->rt = (instr >> 12) & 0xf;

	if (Rn == 15)
		return false;

	/* Handle Writeback */
	if (!P && U)
		*kvm_decode_reg(decode, Rn) = offset_addr + imm8;
	else if (!P && !U)
		*kvm_decode_reg(decode, Rn) = offset_addr - imm8;
	return true;
}

static bool decode_thumb_str(struct kvm_decode *decode,
			     struct kvm_exit_mmio *mmio,
			     unsigned long instr, const struct thumb_instr *ti)
{
	u8 op1 = (instr >> (16 + 5)) & 0x7;
	u8 op2 = (instr >> 6) & 0x3f;

	mmio->is_write = true;
	decode->sign_extend = false;

	switch (op1) {
	case 0x0: mmio->len = 1; break;
	case 0x1: mmio->len = 2; break;
	case 0x2: mmio->len = 4; break;
	default:
		  return false; /* Only register write-back versions! */
	}

	if ((op2 & 0x24) == 0x24) {
		/* STRB (immediate, thumb, W=1) */
		return decode_thumb_wb(decode, mmio, instr);
	}

	return false;
}

static bool decode_thumb_ldr(struct kvm_decode *decode,
			     struct kvm_exit_mmio *mmio,
			     unsigned long instr, const struct thumb_instr *ti)
{
	u8 op1 = (instr >> (16 + 7)) & 0x3;
	u8 op2 = (instr >> 6) & 0x3f;

	mmio->is_write = false;

	switch (ti->op2 & 0x7) {
	case 0x1: mmio->len = 1; break;
	case 0x3: mmio->len = 2; break;
	case 0x5: mmio->len = 4; break;
	}

	if (op1 == 0x0)
		decode->sign_extend = false;
	else if (op1 == 0x2 && (ti->op2 & 0x7) != 0x5)
		decode->sign_extend = true;
	else
		return false; /* Only register write-back versions! */

	if ((op2 & 0x24) == 0x24) {
		/* LDR{S}X (immediate, thumb, W=1) */
		return decode_thumb_wb(decode, mmio, instr);
	}

	return false;
}

/*
 * We only support instruction decoding for valid reasonable MMIO operations
 * where trapping them do not provide sufficient information in the HSR (no
 * 16-bit Thumb instructions provide register writeback that we care about).
 *
 * The following instruciton types are NOT supported for MMIO operations
 * despite the HSR not containing decode info:
 *  - any Load/Store multiple
 *  - any load/store exclusive
 *  - any load/store dual
 *  - anything with the PC as the dest register
 */
static const struct thumb_instr thumb_instr[] = {
	/**************** 32-bit Thumb instructions **********************/
	/* Store single data item:	Op1 == 11, Op2 == 000xxx0 */
	{ .is32 = true,  .opcode = 3, .op2 = 0x00, .op2_mask = 0x71,
						decode_thumb_str	},

	/* Load byte:			Op1 == 11, Op2 == 00xx001 */
	{ .is32 = true,  .opcode = 3, .op2 = 0x01, .op2_mask = 0x67,
						decode_thumb_ldr	},

	/* Load halfword:		Op1 == 11, Op2 == 00xx011 */
	{ .is32 = true,  .opcode = 3, .op2 = 0x03, .op2_mask = 0x67,
						decode_thumb_ldr	},

	/* Load word:			Op1 == 11, Op2 == 00xx101 */
	{ .is32 = true,  .opcode = 3, .op2 = 0x05, .op2_mask = 0x67,
						decode_thumb_ldr	},
};



static bool kvm_decode_thumb_ls(struct kvm_decode *decode, unsigned long instr,
				struct kvm_exit_mmio *mmio)
{
	bool is32 = is_wide_instruction(instr);
	bool is16 = !is32;
	struct thumb_instr tinstr; /* re-use to pass on already decoded info */
	int i;

	if (is16) {
		tinstr.opcode = (instr >> 10) & 0x3f;
	} else {
		tinstr.opcode = (instr >> (16 + 11)) & 0x3;
		tinstr.op2 = (instr >> (16 + 4)) & 0x7f;
	}

	for (i = 0; i < ARRAY_SIZE(thumb_instr); i++) {
		const struct thumb_instr *ti = &thumb_instr[i];
		if (ti->is32 != is32)
			continue;

		if (is16) {
			if ((tinstr.opcode & ti->opcode_mask) != ti->opcode)
				continue;
		} else {
			if (ti->opcode != tinstr.opcode)
				continue;
			if ((ti->op2_mask & tinstr.op2) != ti->op2)
				continue;
		}

		return ti->decode(decode, mmio, instr, &tinstr);
	}

	return false;
}

/**
 * kvm_decode_load_store - decodes load/store instructions
 * @decode: reads regs and fault_addr, writes rt and sign_extend
 * @instr:  instruction to decode
 * @mmio:   fills in len and is_write
 *
 * Decode load/store instructions with HSR ISV clear. The code assumes that
 * this was indeed a KVM fault and therefore assumes registers write back for
 * single load/store operations and does not support using the PC as the
 * destination register.
 */
int kvm_decode_load_store(struct kvm_decode *decode, unsigned long instr,
			  struct kvm_exit_mmio *mmio)
{
	bool is_thumb;

	is_thumb = !!(*kvm_decode_cpsr(decode) & PSR_T_BIT);
	if (!is_thumb)
		return kvm_decode_arm_ls(decode, instr, mmio) ? 0 : 1;
	else
		return kvm_decode_thumb_ls(decode, instr, mmio) ? 0 : 1;
}
