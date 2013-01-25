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

#ifdef CONFIG_ARM_RUNTIME_PATCH_TEST

struct patch_test_imm8 {
	u16	imm;
	u16	shift;
	u32	insn;
};

static void __init __used __naked __patch_test_code_imm8(void)
{
	__asm__ __volatile__ (

		/* a single test case */
		"	.macro		test_one, imm, sft\n"
		"	.hword		\\imm\n"
		"	.hword		\\sft\n"
		"	add		r1, r2, #(\\imm << \\sft)\n"
		"	.endm\n"

		/* a sequence of tests at 'inc' increments of shift */
		"	.macro		test_seq, imm, sft, max, inc\n"
		"	test_one	\\imm, \\sft\n"
		"	.if		\\sft < \\max\n"
		"	test_seq	\\imm, (\\sft + \\inc), \\max, \\inc\n"
		"	.endif\n"
		"	.endm\n"

		/* an empty record to mark the end */
		"	.macro		test_end\n"
		"	.hword		0, 0\n"
		"	.word		0\n"
		"	.endm\n"

		/* finally generate the test sequences */
		"	test_seq	0x41, 0, 24, 1\n"
		"	test_seq	0x81, 0, 24, 2\n"
		"	test_end\n"
		: : : "r1", "r2", "cc");
}

static void __init test_patch_imm8(void)
{
	u32 test_code_addr = (u32)(&__patch_test_code_imm8);
	struct patch_test_imm8 *test = (void *)(test_code_addr & ~1);
	u32 ninsn, insn, patched_insn;
	int i, err;

	insn = test[0].insn;
	for (i = 0; test[i].insn; i++) {
		err = do_patch_imm8(insn, test[i].imm << test[i].shift, &ninsn);
		__patch_text(&patched_insn, ninsn);

		if (err) {
			pr_err("rtpatch imm8: failed at imm %x, shift %d\n",
			       test[i].imm, test[i].shift);
		} else if (patched_insn != test[i].insn) {
			pr_err("rtpatch imm8: failed, need %x got %x\n",
			       test[i].insn, patched_insn);
		} else {
			pr_debug("rtpatch imm8: imm %x, shift %d, %x -> %x\n",
				 test[i].imm, test[i].shift, insn,
				 patched_insn);
		}
	}
}

static void __init runtime_patch_test(void)
{
	test_patch_imm8();
}
#endif

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

#ifdef CONFIG_ARM_RUNTIME_PATCH_TEST
	runtime_patch_test();
#endif
	BUG_ON(runtime_patch(start, end - start));
}
