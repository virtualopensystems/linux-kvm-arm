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

#include <linux/mm.h>
#include <linux/kvm_host.h>
#include <asm/kvm_arm.h>
#include <asm/kvm_emulate.h>
#include <trace/events/kvm.h>

#include "trace.h"

#define VCPU_NR_MODES 6
#define REG_OFFSET(_reg) \
	(offsetof(struct kvm_regs, _reg) / sizeof(u32))

#define USR_REG_OFFSET(_num) REG_OFFSET(usr_regs[_num])

static const unsigned long vcpu_reg_offsets[VCPU_NR_MODES][15] = {
	/* USR/SYS Registers */
	{
		USR_REG_OFFSET(0), USR_REG_OFFSET(1), USR_REG_OFFSET(2),
		USR_REG_OFFSET(3), USR_REG_OFFSET(4), USR_REG_OFFSET(5),
		USR_REG_OFFSET(6), USR_REG_OFFSET(7), USR_REG_OFFSET(8),
		USR_REG_OFFSET(9), USR_REG_OFFSET(10), USR_REG_OFFSET(11),
		USR_REG_OFFSET(12), USR_REG_OFFSET(13),	USR_REG_OFFSET(14),
	},

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
	},
};

/*
 * Return a pointer to the register number valid in the current mode of
 * the virtual CPU.
 */
u32 *vcpu_reg(struct kvm_vcpu *vcpu, u8 reg_num)
{
	u32 *reg_array = (u32 *)&vcpu->arch.regs;
	u32 mode = *vcpu_cpsr(vcpu) & MODE_MASK;

	BUG_ON(reg_num >= 15);

	switch (mode) {
	case USR_MODE...SVC_MODE:
		mode &= ~MODE32_BIT; /* 0 ... 3 */
		break;

	case ABT_MODE:
		mode = 4;
		break;

	case UND_MODE:
		mode = 5;
		break;

	case SYSTEM_MODE:
		mode = 0;
		break;

	default:
		BUG();
	}

	return reg_array + vcpu_reg_offsets[mode][reg_num];
}

/*
 * Return the SPSR for the current mode of the virtual CPU.
 */
u32 *vcpu_spsr(struct kvm_vcpu *vcpu)
{
	u32 mode = *vcpu_cpsr(vcpu) & MODE_MASK;
	switch (mode) {
	case SVC_MODE:
		return &vcpu->arch.regs.svc_regs[2];
	case ABT_MODE:
		return &vcpu->arch.regs.abt_regs[2];
	case UND_MODE:
		return &vcpu->arch.regs.und_regs[2];
	case IRQ_MODE:
		return &vcpu->arch.regs.irq_regs[2];
	case FIQ_MODE:
		return &vcpu->arch.regs.fiq_regs[7];
	default:
		BUG();
	}
}

/**
 * kvm_handle_wfi - handle a wait-for-interrupts instruction executed by a guest
 * @vcpu:	the vcpu pointer
 * @run:	the kvm_run structure pointer
 *
 * Simply sets the wait_for_interrupts flag on the vcpu structure, which will
 * halt execution of world-switches and schedule other host processes until
 * there is an incoming IRQ or FIQ to the VM.
 */
int kvm_handle_wfi(struct kvm_vcpu *vcpu, struct kvm_run *run)
{
	trace_kvm_wfi(*vcpu_pc(vcpu));
	kvm_vcpu_block(vcpu);
	return 1;
}

static u64 kvm_va_to_pa(struct kvm_vcpu *vcpu, u32 va, bool priv)
{
	return kvm_call_hyp(__kvm_va_to_pa, vcpu, va, priv);
}

/**
 * copy_from_guest_va - copy memory from guest (very slow!)
 * @vcpu:	vcpu pointer
 * @dest:	memory to copy into
 * @gva:	virtual address in guest to copy from
 * @len:	length to copy
 * @priv:	use guest PL1 (ie. kernel) mappings
 *              otherwise use guest PL0 mappings.
 *
 * Returns true on success, false on failure (unlikely, but retry).
 */
static bool copy_from_guest_va(struct kvm_vcpu *vcpu,
			       void *dest, unsigned long gva, size_t len,
			       bool priv)
{
	u64 par;
	phys_addr_t pc_ipa;
	int err;

	BUG_ON((gva & PAGE_MASK) != ((gva + len) & PAGE_MASK));
	par = kvm_va_to_pa(vcpu, gva & PAGE_MASK, priv);
	if (par & 1) {
		kvm_err("IO abort from invalid instruction address"
			" %#lx!\n", gva);
		return false;
	}

	BUG_ON(!(par & (1U << 11)));
	pc_ipa = par & PAGE_MASK & ((1ULL << 32) - 1);
	pc_ipa += gva & ~PAGE_MASK;


	err = kvm_read_guest(vcpu->kvm, pc_ipa, dest, len);
	if (unlikely(err))
		return false;

	return true;
}

/* Just ensure we're not running the guest. */
static void do_nothing(void *info)
{
}

/*
 * We have to be very careful copying memory from a running (ie. SMP) guest.
 * Another CPU may remap the page (eg. swap out a userspace text page) as we
 * read the instruction.  Unlike normal hardware operation, to emulate an
 * instruction we map the virtual to physical address then read that memory
 * as separate steps, thus not atomic.
 *
 * Fortunately this is so rare (we don't usually need the instruction), we
 * can go very slowly and noone will mind.
 */
static bool copy_current_insn(struct kvm_vcpu *vcpu, unsigned long *instr)
{
	int i;
	bool ret;
	struct kvm_vcpu *v;
	bool is_thumb;
	size_t instr_len;

	/* Don't cross with IPIs in kvm_main.c */
	spin_lock(&vcpu->kvm->mmu_lock);

	/* Tell them all to pause, so no more will enter guest. */
	kvm_for_each_vcpu(i, v, vcpu->kvm)
		v->arch.pause = true;

	/* Set ->pause before we read ->mode */
	smp_mb();

	/* Kick out any which are still running. */
	kvm_for_each_vcpu(i, v, vcpu->kvm) {
		/* Guest could exit now, making cpu wrong. That's OK. */
		if (kvm_vcpu_exiting_guest_mode(v) == IN_GUEST_MODE)
			smp_call_function_single(v->cpu, do_nothing, NULL, 1);
	}


	is_thumb = !!(*vcpu_cpsr(vcpu) & PSR_T_BIT);
	instr_len = (is_thumb) ? 2 : 4;

	BUG_ON(!is_thumb && *vcpu_pc(vcpu) & 0x3);

	/* Now guest isn't running, we can va->pa map and copy atomically. */
	ret = copy_from_guest_va(vcpu, instr, *vcpu_pc(vcpu), instr_len,
				 vcpu_mode_priv(vcpu));
	if (!ret)
		goto out;

	/* A 32-bit thumb2 instruction can actually go over a page boundary! */
	if (is_thumb && is_wide_instruction(*instr)) {
		*instr = *instr << 16;
		ret = copy_from_guest_va(vcpu, instr, *vcpu_pc(vcpu) + 2, 2,
					 vcpu_mode_priv(vcpu));
	}

out:
	/* Release them all. */
	kvm_for_each_vcpu(i, v, vcpu->kvm)
		v->arch.pause = false;

	spin_unlock(&vcpu->kvm->mmu_lock);

	return ret;
}

/******************************************************************************
 * Load-Store instruction emulation
 *****************************************************************************/

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

	bool (*decode)(struct kvm_vcpu *vcpu, struct kvm_exit_mmio *mmio,
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
enum SRType decode_imm_shift(u8 type, u8 imm5, u8 *amount)
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
u32 shift(u32 value, u8 N, enum SRType type, u8 amount, bool carry_in)
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

static bool decode_arm_wb(struct kvm_vcpu *vcpu, struct kvm_exit_mmio *mmio,
			  unsigned long instr, const struct arm_instr *ai)
{
	u8 Rt = (instr >> 12) & 0xf;
	u8 Rn = (instr >> 16) & 0xf;
	u8 W = (instr >> 21) & 1;
	u8 U = (instr >> 23) & 1;
	u8 P = (instr >> 24) & 1;
	u32 base_addr = *vcpu_reg(vcpu, Rn);
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

	vcpu->arch.mmio.rd = Rt;

	if (ai->register_form) {
		/* Register operation */
		enum SRType s_type;
		u8 shift_n;
		bool c_bit = *vcpu_cpsr(vcpu) & PSR_C_BIT;
		u32 s_reg = *vcpu_reg(vcpu, ai->Rm);

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
	*vcpu_reg(vcpu, Rn) = offset_addr;
	return true;
}

static bool decode_arm_ls(struct kvm_vcpu *vcpu, struct kvm_exit_mmio *mmio,
			  unsigned long instr, struct arm_instr *ai)
{
	u8 A = (instr >> 25) & 1;

	mmio->is_write = ai->w;
	mmio->len = ai->len;
	vcpu->arch.mmio.sign_extend = false;

	ai->register_form = A;
	ai->imm = instr & 0xfff;
	ai->Rm = instr & 0xf;
	ai->type = (instr >> 5) & 0x3;
	ai->shift_n = (instr >> 7) & 0x1f;

	return decode_arm_wb(vcpu, mmio, instr, ai);
}

static bool decode_arm_extra(struct kvm_vcpu *vcpu, struct kvm_exit_mmio *mmio,
			     unsigned long instr, struct arm_instr *ai)
{
	mmio->is_write = ai->w;
	mmio->len = ai->len;
	vcpu->arch.mmio.sign_extend = ai->sign_extend;

	ai->register_form = !((instr >> 22) & 1);
	ai->imm = ((instr >> 4) & 0xf0) | (instr & 0xf);
	ai->Rm = instr & 0xf;
	ai->type = 0; /* SRType_LSL */
	ai->shift_n = 0;

	return decode_arm_wb(vcpu, mmio, instr, ai);
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

static bool kvm_decode_arm_ls(struct kvm_vcpu *vcpu, unsigned long instr,
			      struct kvm_exit_mmio *mmio)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(arm_instr); i++) {
		const struct arm_instr *ai = &arm_instr[i];
		if ((instr & ai->opc_mask) == ai->opc) {
			struct arm_instr ai_copy = *ai;
			return ai->decode(vcpu, mmio, instr, &ai_copy);
		}
	}
	return false;
}

struct thumb_instr {
	bool is32;

	union {
		struct {
			u8 opcode;
			u8 mask;
		} t16;

		struct {
			u8 op1;
			u8 op2;
			u8 op2_mask;
		} t32;
	};

	bool (*decode)(struct kvm_vcpu *vcpu, struct kvm_exit_mmio *mmio,
		       unsigned long instr, const struct thumb_instr *ti);
};

static bool decode_thumb_wb(struct kvm_vcpu *vcpu, struct kvm_exit_mmio *mmio,
			    unsigned long instr)
{
	bool P = (instr >> 10) & 1;
	bool U = (instr >> 9) & 1;
	u8 imm8 = instr & 0xff;
	u32 offset_addr = vcpu->arch.hxfar;
	u8 Rn = (instr >> 16) & 0xf;

	vcpu->arch.mmio.rd = (instr >> 12) & 0xf;

	if (kvm_vcpu_reg_is_pc(vcpu, Rn))
		return false;

	/* Handle Writeback */
	if (!P && U)
		*vcpu_reg(vcpu, Rn) = offset_addr + imm8;
	else if (!P && !U)
		*vcpu_reg(vcpu, Rn) = offset_addr - imm8;
	return true;
}

static bool decode_thumb_str(struct kvm_vcpu *vcpu, struct kvm_exit_mmio *mmio,
			     unsigned long instr, const struct thumb_instr *ti)
{
	u8 op1 = (instr >> (16 + 5)) & 0x7;
	u8 op2 = (instr >> 6) & 0x3f;

	mmio->is_write = true;
	vcpu->arch.mmio.sign_extend = false;

	switch (op1) {
	case 0x0: mmio->len = 1; break;
	case 0x1: mmio->len = 2; break;
	case 0x2: mmio->len = 4; break;
	default:
		  return false; /* Only register write-back versions! */
	}

	if ((op2 & 0x24) == 0x24) {
		/* STRB (immediate, thumb, W=1) */
		return decode_thumb_wb(vcpu, mmio, instr);
	}

	return false;
}

static bool decode_thumb_ldr(struct kvm_vcpu *vcpu, struct kvm_exit_mmio *mmio,
			     unsigned long instr, const struct thumb_instr *ti)
{
	u8 op1 = (instr >> (16 + 7)) & 0x3;
	u8 op2 = (instr >> 6) & 0x3f;

	mmio->is_write = false;

	switch (ti->t32.op2 & 0x7) {
	case 0x1: mmio->len = 1; break;
	case 0x3: mmio->len = 2; break;
	case 0x5: mmio->len = 4; break;
	}

	if (op1 == 0x0)
		vcpu->arch.mmio.sign_extend = false;
	else if (op1 == 0x2 && (ti->t32.op2 & 0x7) != 0x5)
		vcpu->arch.mmio.sign_extend = true;
	else
		return false; /* Only register write-back versions! */

	if ((op2 & 0x24) == 0x24) {
		/* LDR{S}X (immediate, thumb, W=1) */
		return decode_thumb_wb(vcpu, mmio, instr);
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
	{ .is32 = true,  .t32 = { 3, 0x00, 0x71}, decode_thumb_str	},
	/* Load byte:			Op1 == 11, Op2 == 00xx001 */
	{ .is32 = true,  .t32 = { 3, 0x01, 0x67}, decode_thumb_ldr	},
	/* Load halfword:		Op1 == 11, Op2 == 00xx011 */
	{ .is32 = true,  .t32 = { 3, 0x03, 0x67}, decode_thumb_ldr	},
	/* Load word:			Op1 == 11, Op2 == 00xx101 */
	{ .is32 = true,  .t32 = { 3, 0x05, 0x67}, decode_thumb_ldr	},
};



static bool kvm_decode_thumb_ls(struct kvm_vcpu *vcpu, unsigned long instr,
				struct kvm_exit_mmio *mmio)
{
	bool is32 = is_wide_instruction(instr);
	bool is16 = !is32;
	struct thumb_instr tinstr; /* re-use to pass on already decoded info */
	int i;

	if (is16) {
		tinstr.t16.opcode = (instr >> 10) & 0x3f;
	} else {
		tinstr.t32.op1 = (instr >> (16 + 11)) & 0x3;
		tinstr.t32.op2 = (instr >> (16 + 4)) & 0x7f;
	}

	for (i = 0; i < ARRAY_SIZE(thumb_instr); i++) {
		const struct thumb_instr *ti = &thumb_instr[i];
		if (ti->is32 != is32)
			continue;

		if (is16) {
			if ((tinstr.t16.opcode & ti->t16.mask) != ti->t16.opcode)
				continue;
		} else {
			if (ti->t32.op1 != tinstr.t32.op1)
				continue;
			if ((ti->t32.op2_mask & tinstr.t32.op2) != ti->t32.op2)
				continue;
		}

		return ti->decode(vcpu, mmio, instr, &tinstr);
	}

	return false;
}

/**
 * kvm_emulate_mmio_ls - emulates load/store instructions made to I/O memory
 * @vcpu:	The vcpu pointer
 * @fault_ipa:	The IPA that caused the 2nd stage fault
 * @mmio:      Pointer to struct to hold decode information
 *
 * Some load/store instructions cannot be emulated using the information
 * presented in the HSR, for instance, register write-back instructions are not
 * supported. We therefore need to fetch the instruction, decode it, and then
 * emulate its behavior.
 *
 * Handles emulation of load/store instructions which cannot be emulated through
 * information found in the HSR on faults. It is necessary in this case to
 * simply decode the offending instruction in software and determine the
 * required operands.
 */
int kvm_emulate_mmio_ls(struct kvm_vcpu *vcpu, phys_addr_t fault_ipa,
			struct kvm_exit_mmio *mmio)
{
	bool is_thumb;
	unsigned long instr = 0;

	trace_kvm_mmio_emulate(*vcpu_pc(vcpu), instr, *vcpu_cpsr(vcpu));

	/* If it fails (SMP race?), we reenter guest for it to retry. */
	if (!copy_current_insn(vcpu, &instr))
		return 1;

	mmio->phys_addr = fault_ipa;
	is_thumb = !!(*vcpu_cpsr(vcpu) & PSR_T_BIT);
	if (!is_thumb && !kvm_decode_arm_ls(vcpu, instr, mmio)) {
		kvm_debug("Unable to decode inst: %#08lx (cpsr: %#08x (T=0)"
			  "pc: %#08x)\n",
			  instr, *vcpu_cpsr(vcpu), *vcpu_pc(vcpu));
		kvm_inject_dabt(vcpu, vcpu->arch.hxfar);
		return 1;
	} else if (is_thumb && !kvm_decode_thumb_ls(vcpu, instr, mmio)) {
		kvm_debug("Unable to decode inst: %#08lx (cpsr: %#08x (T=1)"
			  "pc: %#08x)\n",
			  instr, *vcpu_cpsr(vcpu), *vcpu_pc(vcpu));
		kvm_inject_dabt(vcpu, vcpu->arch.hxfar);
		return 1;
	}

	/*
	 * The MMIO instruction is emulated and should not be re-executed
	 * in the guest.
	 */
	kvm_skip_instr(vcpu, is_wide_instruction(instr));
	return 0;
}

/**
 * adjust_itstate - adjust ITSTATE when emulating instructions in IT-block
 * @vcpu:	The VCPU pointer
 *
 * When exceptions occur while instructions are executed in Thumb IF-THEN
 * blocks, the ITSTATE field of the CPSR is not advanved (updated), so we have
 * to do this little bit of work manually. The fields map like this:
 *
 * IT[7:0] -> CPSR[26:25],CPSR[15:10]
 */
static void kvm_adjust_itstate(struct kvm_vcpu *vcpu)
{
	unsigned long itbits, cond;
	unsigned long cpsr = *vcpu_cpsr(vcpu);
	bool is_arm = !(cpsr & PSR_T_BIT);

	BUG_ON(is_arm && (cpsr & PSR_IT_MASK));

	if (!(cpsr & PSR_IT_MASK))
		return;

	cond = (cpsr & 0xe000) >> 13;
	itbits = (cpsr & 0x1c00) >> (10 - 2);
	itbits |= (cpsr & (0x3 << 25)) >> 25;

	/* Perform ITAdvance (see page A-52 in ARM DDI 0406C) */
	if ((itbits & 0x7) == 0)
		itbits = cond = 0;
	else
		itbits = (itbits << 1) & 0x1f;

	cpsr &= ~PSR_IT_MASK;
	cpsr |= cond << 13;
	cpsr |= (itbits & 0x1c) << (10 - 2);
	cpsr |= (itbits & 0x3) << 25;
	*vcpu_cpsr(vcpu) = cpsr;
}

/**
 * kvm_skip_instr - skip a trapped instruction and proceed to the next
 * @vcpu: The vcpu pointer
 */
void kvm_skip_instr(struct kvm_vcpu *vcpu, bool is_wide_instr)
{
	bool is_thumb;

	is_thumb = !!(*vcpu_cpsr(vcpu) & PSR_T_BIT);
	if (is_thumb && !is_wide_instr)
		*vcpu_pc(vcpu) += 2;
	else
		*vcpu_pc(vcpu) += 4;
	kvm_adjust_itstate(vcpu);
}


/******************************************************************************
 * Inject exceptions into the guest
 */

static u32 exc_vector_base(struct kvm_vcpu *vcpu)
{
	u32 sctlr = vcpu->arch.cp15[c1_SCTLR];
	u32 vbar = vcpu->arch.cp15[c12_VBAR];

	if (sctlr & SCTLR_V)
		return 0xffff0000;
	else /* always have security exceptions */
		return vbar;
}

/**
 * kvm_inject_undefined - inject an undefined exception into the guest
 * @vcpu: The VCPU to receive the undefined exception
 *
 * It is assumed that this code is called from the VCPU thread and that the
 * VCPU therefore is not currently executing guest code.
 *
 * Modelled after TakeUndefInstrException() pseudocode.
 */
void kvm_inject_undefined(struct kvm_vcpu *vcpu)
{
	u32 new_lr_value;
	u32 new_spsr_value;
	u32 cpsr = *vcpu_cpsr(vcpu);
	u32 sctlr = vcpu->arch.cp15[c1_SCTLR];
	bool is_thumb = (cpsr & PSR_T_BIT);
	u32 vect_offset = 4;
	u32 return_offset = (is_thumb) ? 2 : 4;

	new_spsr_value = cpsr;
	new_lr_value = *vcpu_pc(vcpu) - return_offset;

	*vcpu_cpsr(vcpu) = (cpsr & ~MODE_MASK) | UND_MODE;
	*vcpu_cpsr(vcpu) |= PSR_I_BIT;
	*vcpu_cpsr(vcpu) &= ~(PSR_IT_MASK | PSR_J_BIT | PSR_E_BIT | PSR_T_BIT);

	if (sctlr & SCTLR_TE)
		*vcpu_cpsr(vcpu) |= PSR_T_BIT;
	if (sctlr & SCTLR_EE)
		*vcpu_cpsr(vcpu) |= PSR_E_BIT;

	/* Note: These now point to UND banked copies */
	*vcpu_spsr(vcpu) = cpsr;
	*vcpu_reg(vcpu, 14) = new_lr_value;

	/* Branch to exception vector */
	*vcpu_pc(vcpu) = exc_vector_base(vcpu) + vect_offset;
}

/*
 * Modelled after TakeDataAbortException() and TakePrefetchAbortException
 * pseudocode.
 */
static void inject_abt(struct kvm_vcpu *vcpu, bool is_pabt, unsigned long addr)
{
	u32 new_lr_value;
	u32 new_spsr_value;
	u32 cpsr = *vcpu_cpsr(vcpu);
	u32 sctlr = vcpu->arch.cp15[c1_SCTLR];
	bool is_thumb = (cpsr & PSR_T_BIT);
	u32 vect_offset;
	u32 return_offset = (is_thumb) ? 4 : 0;
	bool is_lpae;

	new_spsr_value = cpsr;
	new_lr_value = *vcpu_pc(vcpu) + return_offset;

	*vcpu_cpsr(vcpu) = (cpsr & ~MODE_MASK) | ABT_MODE;
	*vcpu_cpsr(vcpu) |= PSR_I_BIT | PSR_A_BIT;
	*vcpu_cpsr(vcpu) &= ~(PSR_IT_MASK | PSR_J_BIT | PSR_E_BIT | PSR_T_BIT);

	if (sctlr & SCTLR_TE)
		*vcpu_cpsr(vcpu) |= PSR_T_BIT;
	if (sctlr & SCTLR_EE)
		*vcpu_cpsr(vcpu) |= PSR_E_BIT;

	/* Note: These now point to ABT banked copies */
	*vcpu_spsr(vcpu) = cpsr;
	*vcpu_reg(vcpu, 14) = new_lr_value;

	if (is_pabt)
		vect_offset = 12;
	else
		vect_offset = 16;

	/* Branch to exception vector */
	*vcpu_pc(vcpu) = exc_vector_base(vcpu) + vect_offset;

	if (is_pabt) {
		/* Set DFAR and DFSR */
		vcpu->arch.cp15[c6_IFAR] = addr;
		is_lpae = (vcpu->arch.cp15[c2_TTBCR] >> 31);
		/* Always give debug fault for now - should give guest a clue */
		if (is_lpae)
			vcpu->arch.cp15[c5_IFSR] = 1 << 9 | 0x22;
		else
			vcpu->arch.cp15[c5_IFSR] = 2;
	} else { /* !iabt */
		/* Set DFAR and DFSR */
		vcpu->arch.cp15[c6_DFAR] = addr;
		is_lpae = (vcpu->arch.cp15[c2_TTBCR] >> 31);
		/* Always give debug fault for now - should give guest a clue */
		if (is_lpae)
			vcpu->arch.cp15[c5_DFSR] = 1 << 9 | 0x22;
		else
			vcpu->arch.cp15[c5_DFSR] = 2;
	}

}

/**
 * kvm_inject_dabt - inject a data abort into the guest
 * @vcpu: The VCPU to receive the undefined exception
 * @addr: The address to report in the DFAR
 *
 * It is assumed that this code is called from the VCPU thread and that the
 * VCPU therefore is not currently executing guest code.
 */
void kvm_inject_dabt(struct kvm_vcpu *vcpu, unsigned long addr)
{
	inject_abt(vcpu, false, addr);
}

/**
 * kvm_inject_pabt - inject a prefetch abort into the guest
 * @vcpu: The VCPU to receive the undefined exception
 * @addr: The address to report in the DFAR
 *
 * It is assumed that this code is called from the VCPU thread and that the
 * VCPU therefore is not currently executing guest code.
 */
void kvm_inject_pabt(struct kvm_vcpu *vcpu, unsigned long addr)
{
	inject_abt(vcpu, true, addr);
}
