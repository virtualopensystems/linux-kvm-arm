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

#define USR_REG_OFFSET(_num) REG_OFFSET(usr_regs.uregs[_num])

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


/******************************************************************************
 * Load-Store instruction emulation
 *****************************************************************************/

/*
 * This one accepts a matrix where the first element is the
 * bits as they must be, and the second element is the bitmask.
 */
#define INSTR_NONE	-1
static int kvm_instr_index(u32 instr, u32 table[][2], int table_entries)
{
	int i;
	u32 mask;

	for (i = 0; i < table_entries; i++) {
		mask = table[i][1];
		if ((table[i][0] & mask) == (instr & mask))
			return i;
	}
	return INSTR_NONE;
}

/*
 * Must be ordered with LOADS first and WRITES afterwards
 * for easy distinction when doing MMIO.
 */
#define NUM_LD_INSTR  9
enum INSTR_LS_INDEXES {
	INSTR_LS_LDRBT, INSTR_LS_LDRT, INSTR_LS_LDR, INSTR_LS_LDRB,
	INSTR_LS_LDRD, INSTR_LS_LDREX, INSTR_LS_LDRH, INSTR_LS_LDRSB,
	INSTR_LS_LDRSH,
	INSTR_LS_STRBT, INSTR_LS_STRT, INSTR_LS_STR, INSTR_LS_STRB,
	INSTR_LS_STRD, INSTR_LS_STREX, INSTR_LS_STRH,
	NUM_LS_INSTR
};

static u32 ls_instr[NUM_LS_INSTR][2] = {
	{0x04700000, 0x0d700000}, /* LDRBT */
	{0x04300000, 0x0d700000}, /* LDRT  */
	{0x04100000, 0x0c500000}, /* LDR   */
	{0x04500000, 0x0c500000}, /* LDRB  */
	{0x000000d0, 0x0e1000f0}, /* LDRD  */
	{0x01900090, 0x0ff000f0}, /* LDREX */
	{0x001000b0, 0x0e1000f0}, /* LDRH  */
	{0x001000d0, 0x0e1000f0}, /* LDRSB */
	{0x001000f0, 0x0e1000f0}, /* LDRSH */
	{0x04600000, 0x0d700000}, /* STRBT */
	{0x04200000, 0x0d700000}, /* STRT  */
	{0x04000000, 0x0c500000}, /* STR   */
	{0x04400000, 0x0c500000}, /* STRB  */
	{0x000000f0, 0x0e1000f0}, /* STRD  */
	{0x01800090, 0x0ff000f0}, /* STREX */
	{0x000000b0, 0x0e1000f0}  /* STRH  */
};

static inline int get_arm_ls_instr_index(u32 instr)
{
	return kvm_instr_index(instr, ls_instr, NUM_LS_INSTR);
}

/*
 * Load-Store instruction decoding
 */
#define INSTR_LS_TYPE_BIT		26
#define INSTR_LS_RD_MASK		0x0000f000
#define INSTR_LS_RD_SHIFT		12
#define INSTR_LS_RN_MASK		0x000f0000
#define INSTR_LS_RN_SHIFT		16
#define INSTR_LS_RM_MASK		0x0000000f
#define INSTR_LS_OFFSET12_MASK		0x00000fff

#define INSTR_LS_BIT_P			24
#define INSTR_LS_BIT_U			23
#define INSTR_LS_BIT_B			22
#define INSTR_LS_BIT_W			21
#define INSTR_LS_BIT_L			20
#define INSTR_LS_BIT_S			 6
#define INSTR_LS_BIT_H			 5

/*
 * ARM addressing mode defines
 */
#define OFFSET_IMM_MASK			0x0e000000
#define OFFSET_IMM_VALUE		0x04000000
#define OFFSET_REG_MASK			0x0e000ff0
#define OFFSET_REG_VALUE		0x06000000
#define OFFSET_SCALE_MASK		0x0e000010
#define OFFSET_SCALE_VALUE		0x06000000

#define SCALE_SHIFT_MASK		0x000000a0
#define SCALE_SHIFT_SHIFT		5
#define SCALE_SHIFT_LSL			0x0
#define SCALE_SHIFT_LSR			0x1
#define SCALE_SHIFT_ASR			0x2
#define SCALE_SHIFT_ROR_RRX		0x3
#define SCALE_SHIFT_IMM_MASK		0x00000f80
#define SCALE_SHIFT_IMM_SHIFT		6

#define PSR_BIT_C			29

static unsigned long ls_word_calc_offset(struct kvm_vcpu *vcpu,
					 unsigned long instr)
{
	int offset = 0;

	if ((instr & OFFSET_IMM_MASK) == OFFSET_IMM_VALUE) {
		/* Immediate offset/index */
		offset = instr & INSTR_LS_OFFSET12_MASK;

		if (!(instr & (1U << INSTR_LS_BIT_U)))
			offset = -offset;
	}

	if ((instr & OFFSET_REG_MASK) == OFFSET_REG_VALUE) {
		/* Register offset/index */
		u8 rm = instr & INSTR_LS_RM_MASK;
		offset = *vcpu_reg(vcpu, rm);

		if (!(instr & (1U << INSTR_LS_BIT_P)))
			offset = 0;
	}

	if ((instr & OFFSET_SCALE_MASK) == OFFSET_SCALE_VALUE) {
		/* Scaled register offset */
		u8 rm = instr & INSTR_LS_RM_MASK;
		u8 shift = (instr & SCALE_SHIFT_MASK) >> SCALE_SHIFT_SHIFT;
		u32 shift_imm = (instr & SCALE_SHIFT_IMM_MASK)
				>> SCALE_SHIFT_IMM_SHIFT;
		offset = *vcpu_reg(vcpu, rm);

		switch (shift) {
		case SCALE_SHIFT_LSL:
			offset = offset << shift_imm;
			break;
		case SCALE_SHIFT_LSR:
			if (shift_imm == 0)
				offset = 0;
			else
				offset = ((u32)offset) >> shift_imm;
			break;
		case SCALE_SHIFT_ASR:
			if (shift_imm == 0) {
				if (offset & (1U << 31))
					offset = 0xffffffff;
				else
					offset = 0;
			} else {
				/* Ensure arithmetic shift */
				asm("mov %[r], %[op], ASR %[s]" :
				    [r] "=r" (offset) :
				    [op] "r" (offset), [s] "r" (shift_imm));
			}
			break;
		case SCALE_SHIFT_ROR_RRX:
			if (shift_imm == 0) {
				u32 C = (*vcpu_cpsr(vcpu) & (1U << PSR_BIT_C));
				offset = (C << 31) | offset >> 1;
			} else {
				/* Ensure arithmetic shift */
				asm("mov %[r], %[op], ASR %[s]" :
				    [r] "=r" (offset) :
				    [op] "r" (offset), [s] "r" (shift_imm));
			}
			break;
		}

		if (instr & (1U << INSTR_LS_BIT_U))
			return offset;
		else
			return -offset;
	}

	if (instr & (1U << INSTR_LS_BIT_U))
		return offset;
	else
		return -offset;

	BUG();
}

static int kvm_ls_length(struct kvm_vcpu *vcpu, u32 instr)
{
	int index;

	index = get_arm_ls_instr_index(instr);

	if (instr & (1U << INSTR_LS_TYPE_BIT)) {
		/* LS word or unsigned byte */
		if (instr & (1U << INSTR_LS_BIT_B))
			return sizeof(unsigned char);
		else
			return sizeof(u32);
	} else {
		/* LS halfword, doubleword or signed byte */
		u32 H = (instr & (1U << INSTR_LS_BIT_H));
		u32 S = (instr & (1U << INSTR_LS_BIT_S));
		u32 L = (instr & (1U << INSTR_LS_BIT_L));

		if (!L && S) {
			kvm_err("WARNING: d-word for MMIO\n");
			return 2 * sizeof(u32);
		} else if (L && S && !H)
			return sizeof(char);
		else
			return sizeof(u16);
	}

	BUG();
}

static bool kvm_decode_arm_ls(struct kvm_vcpu *vcpu, unsigned long instr,
			      struct kvm_exit_mmio *mmio)
{
	int index;
	bool is_write;
	unsigned long rd, rn, offset, len;

	index = get_arm_ls_instr_index(instr);
	if (index == INSTR_NONE)
		return false;

	is_write = (index < NUM_LD_INSTR) ? false : true;
	rd = (instr & INSTR_LS_RD_MASK) >> INSTR_LS_RD_SHIFT;
	len = kvm_ls_length(vcpu, instr);

	mmio->is_write = is_write;
	mmio->len = len;

	vcpu->arch.mmio.sign_extend = false;
	vcpu->arch.mmio.rd = rd;

	/* Handle base register writeback */
	if (!(instr & (1U << INSTR_LS_BIT_P)) ||
	     (instr & (1U << INSTR_LS_BIT_W))) {
		rn = (instr & INSTR_LS_RN_MASK) >> INSTR_LS_RN_SHIFT;
		offset = ls_word_calc_offset(vcpu, instr);
		*vcpu_reg(vcpu, rn) += offset;
	}

	return true;
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
 * @instr:	The instruction that caused the fault
 *
 * Handles emulation of load/store instructions which cannot be emulated through
 * information found in the HSR on faults. It is necessary in this case to
 * simply decode the offending instruction in software and determine the
 * required operands.
 */
int kvm_emulate_mmio_ls(struct kvm_vcpu *vcpu, phys_addr_t fault_ipa,
			unsigned long instr, struct kvm_exit_mmio *mmio)
{
	bool is_thumb;

	trace_kvm_mmio_emulate(*vcpu_pc(vcpu), instr, *vcpu_cpsr(vcpu));

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
