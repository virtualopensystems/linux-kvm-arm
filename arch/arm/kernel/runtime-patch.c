/*
 * arch/arm/kernel/runtime-patch.c
 *
 * Copyright 2012 Texas Instruments, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#include <linux/kernel.h>
#include <linux/sched.h>

#include <asm/opcodes.h>
#include <asm/cacheflush.h>
#include <asm/runtime-patch.h>

#include "patch.h"

static inline void flush_icache_insn(void *insn_ptr, int bytes)
{
	unsigned long insn_addr = (unsigned long)insn_ptr;
	flush_icache_range(insn_addr, insn_addr + bytes - 1);
}

#ifdef CONFIG_THUMB2_KERNEL

static int do_patch_imm8(u32 insn, u32 imm, u32 *ninsn)
{
	u32 op, rot, val;
	const u32 supported_ops = (BIT(0)  | /* and */
				   BIT(1)  | /* bic */
				   BIT(2)  | /* orr/mov */
				   BIT(3)  | /* orn/mvn */
				   BIT(4)  | /* eor */
				   BIT(8)  | /* add */
				   BIT(10) | /* adc */
				   BIT(11) | /* sbc */
				   BIT(12) | /* sub */
				   BIT(13)); /* rsb */

	insn = __mem_to_opcode_thumb32(insn);

	if (!__opcode_is_thumb32(insn)) {
		pr_err("patch: invalid thumb2 insn %08x\n", insn);
		return -EINVAL;
	}

	/* allow only data processing (immediate)
	 * 1111 0x0x xxx0 xxxx 0xxx xxxx xxxx xxxx */
	if ((insn & 0xfa008000) != 0xf0000000) {
		pr_err("patch: unknown insn %08x\n", insn);
		return -EINVAL;
	}

	/* extract op code */
	op = (insn >> 21) & 0xf;

	/* disallow unsupported opcodes */
	if ((supported_ops & BIT(op)) == 0) {
		pr_err("patch: unsupported opcode %x\n", op);
		return -EINVAL;
	}

	if (imm <= 0xff) {
		rot = 0;
		val = imm;
	} else {
		rot = 32 - fls(imm); /* clz */
		if (imm & ~(0xff000000 >> rot)) {
			pr_err("patch: constant overflow %08x\n", imm);
			return -EINVAL;
		}
		val  = (imm >> (24 - rot)) & 0x7f;
		rot += 8; /* encoded i:imm3:a */

		/* pack least-sig rot bit into most-sig val bit */
		val |= (rot & 1) << 7;
		rot >>= 1;
	}

	*ninsn  = insn & ~(BIT(26) | 0x7 << 12 | 0xff);
	*ninsn |= (rot >> 3) << 26;	/* field "i" */
	*ninsn |= (rot & 0x7) << 12;	/* field "imm3" */
	*ninsn |= val;

	return 0;
}

#else

static int do_patch_imm8(u32 insn, u32 imm, u32 *ninsn)
{
	u32 rot, val, op;

	insn = __mem_to_opcode_arm(insn);

	/* disallow special unconditional instructions
	 * 1111 xxxx xxxx xxxx xxxx xxxx xxxx xxxx */
	if ((insn >> 24) == 0xf) {
		pr_err("patch: unconditional insn %08x\n", insn);
		return -EINVAL;
	}

	/* allow only data processing (immediate)
	 * xxxx 001x xxxx xxxx xxxx xxxx xxxx xxxx */
	if (((insn >> 25) & 0x3) != 1) {
		pr_err("patch: unknown insn %08x\n", insn);
		return -EINVAL;
	}

	/* extract op code */
	op = (insn >> 20) & 0x1f;

	/* disallow unsupported 10xxx op codes */
	if (((op >> 3) & 0x3) == 2) {
		pr_err("patch: unsupported opcode %08x\n", insn);
		return -EINVAL;
	}

	rot = imm ? __ffs(imm) / 2 : 0;
	val = imm >> (rot * 2);
	rot = (-rot) & 0xf;

	/* does this fit in 8-bit? */
	if (val > 0xff) {
		pr_err("patch: constant overflow %08x\n", imm);
		return -EINVAL;
	}

	/* patch in new immediate and rotation */
	*ninsn = (insn & ~0xfff) | (rot << 8) | val;

	return 0;
}

#endif	/* CONFIG_THUMB2_KERNEL */

static int apply_patch_imm8(const struct patch_info *p)
{
	u32 *insn_ptr = p->insn, ninsn;
	int count = p->insn_size / sizeof(u32);
	const struct patch_info_imm8 *info;
	int err;


	if (count <= 0 || p->data_size != count * sizeof(*info)) {
		pr_err("patch: bad patch, insn size %d, data size %d\n",
		       p->insn_size, p->data_size);
		return -EINVAL;
	}

	for (info = patch_data(p); count; count--, info++, insn_ptr++) {
		err = do_patch_imm8(info->insn, *info->imm, &ninsn);
		if (err)
			return err;
		__patch_text(insn_ptr, ninsn);
	}


	return 0;
}

int runtime_patch(const void *table, unsigned size)
{
	const struct patch_info *p = table, *end = (table + size);

	for (p = table; p < end; p = patch_next(p)) {
		int err = -EINVAL;

		if (p->type == PATCH_IMM8)
			err = apply_patch_imm8(p);
		if (err)
			return err;
	}
	return 0;
}

void __init runtime_patch_kernel(void)
{
	extern unsigned __runtime_patch_table_begin, __runtime_patch_table_end;
	const void *start = &__runtime_patch_table_begin;
	const void *end   = &__runtime_patch_table_end;

	BUG_ON(runtime_patch(start, end - start));
}
