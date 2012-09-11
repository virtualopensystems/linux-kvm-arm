#include "guest.h"
#include <stdarg.h>
#include "cp15_test.h"

/* Don't test things we know fail. */
#define XFAIL 1

/* Turning this on tests UNPREDICTABLE instructions, too. */
//#define TEST_UNPREDICTABLE 1

struct test32 {
	const char *name;
	unsigned int crn, opc1, crm, opc2;
	void (*test)(const struct test32 *);
	u32 val;
	u32 mask;
};

extern u32 mcr_insn, mrc_insn, mcrr_insn, mrrc_insn;

/* Only understands %u, %s */
static void printf(const char *fmt, ...)
{
	va_list ap;
	unsigned val;
	char intbuf[20], *p;

	va_start(ap, fmt);
	while (*fmt) {
		if (*fmt != '%') {
			putc(*(fmt++));
			continue;
		}
		fmt++;
		switch (*fmt) {
		case 'u':
			fmt++;
			val = va_arg(ap, int);
			if (!val) {
				putc('0');
				continue;
			}
			p = &intbuf[19];
			*(p--) = '\0';
			while (val) {
				*(p--) = (val % 10) + '0';
				val /= 10;
			}
			print(p+1);
			break;
		case 's':
			fmt++;
			p = va_arg(ap, char *);
			print(p);
			break;
		default:
			putc('%');
			continue;
		}
	}
	va_end(ap);
}

/* Alter mcr or mrc instruction */
static void alter_insn32(u32 *insn,
			 unsigned int opc1,
			 unsigned int crn,
			 unsigned int crm,
			 unsigned int opc2)
{
	/* This actually works in both ARM and Thumb mode. */
	*insn &= 0xFF10FF10;
	*insn |= (opc1 << 21) | (crn << 16) | (opc2 << 5) | crm;
	/* ICIALLU */
	asm("mcr p15, 0, %0, c7, c5, 0"	: : "r" (0));
}

/* Alter mcrr or mrrc instruction */
static void alter_insn64(u32 *insn,
			 unsigned int opc1,
			 unsigned int crm)
{
	/* This actually works in both ARM and Thumb mode. */
	*insn &= 0xFFFFFF00;
	*insn |= (opc1 << 4) | crm;
	/* ICIALLU */
	asm("mcr p15, 0, %0, c7, c5, 0"	: : "r" (0));
}

static bool __attribute__((noinline)) cp15_write(unsigned int opc1,
						 unsigned int crn,
						 unsigned int crm,
						 unsigned int opc2,
						 u32 val)
{
	alter_insn32(&mcr_insn, opc1, crn, crm, opc2);

	skip_undef++;
	undef_count = 0;
	asm volatile(".globl mcr_insn\n"
		     "mcr_insn:\n"
		     "	mcr p15, 0, %0, c0, c0, 0" : : "r"(val) : "memory");
	skip_undef--;

	/* This is incremented if we fault. */
	return undef_count == 0;
}

static bool  __attribute__((noinline)) cp15_read(unsigned int opc1,
						 unsigned int crn,
						 unsigned int crm,
						 unsigned int opc2,
						 u32 *val)
{
	alter_insn32(&mrc_insn, opc1, crn, crm, opc2);
	*val = 0xdeadbeef;

	skip_undef++;
	undef_count = 0;
	asm volatile(".globl mrc_insn\n"
		     "mrc_insn:\n"
		     "	mrc p15, 0, %0, c0, c0, 0" : "=r"(*val) : : "memory");
	skip_undef--;

	/* This is incremented if we fault. */
	return undef_count == 0;
}

static const char *reg_name(const struct test32 *t)
{
	if (!t->name)
		return "Unnamed reg";
	return t->name;
}

static void read_expect(const struct test32 *test, u32 expect, u32 mask)
{
	u32 val;
	if (!cp15_read(test->opc1, test->crn, test->crm, test->opc2, &val)) {
		printf("Unexpected fault"
		       " on mrc p15, %u, <Rt>, c%u, c%u, %u (%s)\n",
		       test->opc1, test->crn, test->crm, test->opc2,
		       reg_name(test));
		fail();
	} else if ((val & mask) != expect) {
		printf("Unexpected mrc p15, %u, <Rt>, c%u, c%u, %u (%s):"
		       " got %u expected %u\n",
		       test->opc1, test->crn, test->crm, test->opc2,
		       reg_name(test), val, expect);
		fail();
	} else
		ok();
}

static void write_ignored(const struct test32 *test)
{
	u32 val = 0xabadc0ff;
	if (!cp15_write(test->opc1, test->crn, test->crm, test->opc2, val)) {
		printf("Unexpected fault"
		       " on mcr p15, %u, <Rt>, c%u, c%u, %u (%s)\n",
		       test->opc1, test->crn, test->crm, test->opc2,
		       reg_name(test));
		fail();
	} else
		ok();
}

static void read_unpredictable(const struct test32 *test)
{
#ifdef TEST_UNPREDICTABLE
	u32 val;
	if (cp15_read(test->opc1, test->crn, test->crm, test->opc2, &val)) {
		printf("Expected fault on"
		       " mrc p15, %u, <Rt>, c%u, c%u, %u (%s): got %u\n",
		       test->opc1, test->crn, test->crm, test->opc2,
		       reg_name(test), val);
		fail();
	} else
		ok();
#endif
}

static void write_unpredictable(const struct test32 *test)
{
#ifdef TEST_UNPREDICTABLE
	if (cp15_write(test->opc1, test->crn, test->crm, test->opc2, 0xabadc0ff)) {
		printf("Expected fault on mcr p15, %u, <Rt>, c%u, c%u, %u (%s)\n",
		       test->opc1, test->crn, test->crm, test->opc2, reg_name(test));
		fail();
	} else
		ok();
#endif
}

static void ro_val(const struct test32 *test)
{
	read_expect(test, test->val, test->mask);
	write_unpredictable(test);
}

/* IminLine could be 3 or 4 (lowest bits). */
static void test_ctr(const struct test32 *test)
{
	u32 val;
	if (cp15_read(test->opc1, test->crn, test->crm, test->opc2, &val)
	    && ((val & 0xF) == 3))
		read_expect(test, test->val | 0x3, test->mask);
	else
		read_expect(test, test->val | 0x4, test->mask);
	write_unpredictable(test);
}

static void ro_wi(const struct test32 *test)
{
	read_expect(test, test->val, test->mask);
	write_ignored(test);
}

static void raz_wi(const struct test32 *test)
{
	read_expect(test, 0, 0xFFFFFFFF);
	write_ignored(test);
}

static u32 read_unknown(const struct test32 *test)
{
	u32 val;
	if (!cp15_read(test->opc1, test->crn, test->crm, test->opc2, &val)) {
		printf("Unexpected fault on mrc p15, %u, <Rt>, c%u, c%u, %u (%s)\n",
		       test->opc1, test->crn, test->crm, test->opc2, reg_name(test));
		fail();
	} else
		ok();
	return val;
}

static void unpredictable(const struct test32 *test)
{
	read_unpredictable(test);
	write_unpredictable(test);
}

/* FIXME: This is OK, for now, but if a guest is migrated to a future CPU,
 * it might expect this to be constant. */
static void ro_as_host(const struct test32 *test)
{
	read_unknown(test);
	write_unpredictable(test);
}

/* This usually means it's tied to another register, and we test there. */
static void ignore(const struct test32 *test)
{
}

static void test_csselr_and_ccsidr(const struct test32 *test)
{
	/* FIXME */
	ignore(test);
}

/* TCMTR should be WI, but it faults (at least under fm, try real hw?) */
static void raz_wi_tcmtr(const struct test32 *test)
{
	read_expect(test, 0, 0xFFFFFFFF);
#ifndef XFAIL
	write_ignored(test);
#endif
}

static void test_sctlr(const struct test32 *test)
{
	/* We assume SBZ means 0.  Complain if it's wrong. */
	read_expect(test, test->val, test->mask);

	/* FIXME: Try frobbing bits (though we write SCTLR.V in guest-base.S) */
}

static void test_ttbr(const struct test32 *test)
{
	/* Initial value is unknown, but values we write there should stick. */
	if (!cp15_write(test->opc1, test->crn, test->crm, test->opc2,
			0xFFFE0000)) {
		printf("Unexpected fault"
		       " on mcr p15, %u, <Rt>, c%u, c%u, %u (%s)\n",
		       test->opc1, test->crn, test->crm, test->opc2,
		       reg_name(test));
		fail();
		return;
	}
	read_expect(test, 0xFFFE0000, 0xFFFFFFFF);
}

static void test_ttbcr(const struct test32 *test)
{
	read_expect(test, 0, 0xFFFFFFFF);
}

static void test_dacr(const struct test32 *test)
{
	u32 val;

	val = read_unknown(test);
	/* Frob top two domains. */
	val ^= 0x90000000;
	if (!cp15_write(test->opc1, test->crn, test->crm, test->opc2, val)) {
		printf("Unexpected fault"
		       " on mrc p15, %u, <Rt>, c%u, c%u, %u (%s)\n",
		       test->opc1, test->crn, test->crm, test->opc2,
		       reg_name(test));
		fail();
	}
}

static void test_dfsr_ifsr(const struct test32 *test)
{
	u32 val;

	read_unknown(test);
	val = 0x00000005; /* A valid value for either DFSR or IFSR. */
	if (!cp15_write(test->opc1, test->crn, test->crm, test->opc2, val)) {
		printf("Unexpected fault"
		       " on mrc p15, %u, <Rt>, c%u, c%u, %u (%s)\n",
		       test->opc1, test->crn, test->crm, test->opc2,
		       reg_name(test));
		fail();
	} else
		read_expect(test, val, 0xFFFFFFFF);
}

/* Everything not in this table is undefined. */
static struct test32 test32_table[] = {
	{ "MIDR", 0, 0, 0, 0, ro_val, 0x412FC0F0, 0xFFFFFFFF },
	{ "CTR", 0, 0, 0, 1, test_ctr, 0x8444C000, 0xFFFFFFFF },
	{ "TCMTR", 0, 0, 0, 2, raz_wi_tcmtr },
	{ "TLBTR", 0, 0, 0, 3, ro_val, 0x00000000, 0xFFFFFFFF },
	{ "MIDR alias", 0, 0, 0, 4, ro_val, 0x412FC0F0, 0xFFFFFFFF },
	{ "MPIDR", 0, 0, 0, 5, ro_val, 0x80000000, 0xFFFFFFFF },
	{ "REVIDR", 0, 0, 0, 6, ro_as_host },
	{ "MIDR alias", 0, 0, 0, 7, ro_val, 0x412FC0F0, 0xFFFFFFFF },
	{ "ID_PFR0", 0, 0, 1, 0, ro_as_host },
	{ "ID_PFR1", 0, 0, 1, 1, ro_as_host },
	{ "ID_DFR0", 0, 0, 1, 2, ro_as_host },
	{ "ID_AFR0", 0, 0, 1, 3, ro_as_host },
	{ "ID_MMFR0", 0, 0, 1, 4, ro_as_host },
	{ "ID_MMFR1", 0, 0, 1, 5, ro_as_host },
	{ "ID_MMFR2", 0, 0, 1, 6, ro_as_host },
	{ "ID_MMFR3", 0, 0, 1, 7, ro_as_host },
	{ "ID_ISAR0", 0, 0, 2, 0, ro_as_host },
	{ "ID_ISAR1", 0, 0, 2, 1, ro_as_host },
	{ "ID_ISAR2", 0, 0, 2, 2, ro_as_host },
	{ "ID_ISAR3", 0, 0, 2, 3, ro_as_host },
	{ "ID_ISAR4", 0, 0, 2, 4, ro_as_host },
	{ "ID_ISAR5", 0, 0, 2, 5, ro_as_host },
	{ "CCSIDR", 0, 1, 0, 0, ignore /* see CSSELR */},
	{ "CLIDR", 0, 1, 0, 1, ro_as_host },
	{ "AIDR", 0, 1, 0, 7, ro_as_host },
	{ "CSSELR", 0, 2, 0, 0, test_csselr_and_ccsidr },

	{ "SCTLR", 1, 0, 0, 0, test_sctlr, 0x00C50078, 0xBDFFDFFF },
	{ "ACTLR", 1, 0, 0, 1, ro_wi, 0, 0xFFFFFFFF },
	{ "CPACR", 1, 0, 0, 2, ro_wi, 0, 0xFFFFFFFF }, /* Assume VFP+NEON */

	{ "TTBR0", 2, 0, 0, 0, test_ttbr },
	{ "TTBR1", 2, 0, 0, 1, test_ttbr },
	{ "TTBCR", 2, 0, 0, 2, test_ttbcr },

	{ "DACR", 3, 0, 0, 0, test_dacr },

	{ "DFSR", 5, 0, 0, 0, test_dfsr_ifsr },
	{ "IFSR", 5, 0, 0, 1, test_dfsr_ifsr },

};

int test(void)
{
	const struct test32 *i, *end;
	unsigned int opc1, crn, crm, opc2;
	u32 val;

	i = test32_table;
	end = test32_table + sizeof(test32_table)/sizeof(test32_table[0]);

	for (crn = 0; crn < 16; crn++) {
		for (opc1 = 0; opc1 < 8; opc1++) {
			for (crm = 0; crm < 16; crm++) {
				for (opc2 = 0; opc2 < 8; opc2++) {
					if (i < end
					    && i->opc1 == opc1
					    && i->crn == crn
					    && i->crm == crm
					    && i->opc2 == opc2) {
						i->test(i);
						i++;
					} else {
						struct test32 t;
						t.opc1 = opc1;
						t.crn = crn;
						t.crm = crm;
						t.opc2 = opc2;
						unpredictable(&t);
					}
				}
			}
		}
	}

	if (i != end) {
		printf("What?  Still got %u remaining!\n", end - i);
		return 2;
	}

	/* Cooperate with the host to check the userspace API, using TTBR0. */
	assert(cp15_write(0, 2, 0, 0, 0x80000000));
	assert(cp15_read(0, 2, 0, 0, &val));
	assert(val == 0x80000000);

	/* Host should see the right value. */
	val = 0xdeadbeef;
	asm volatile("ldr %0, [%1]" : "=r"(val) : "r"(CP15_TTBR0));
	assert(val == 0x80000000);

	/* Host change should make us see the right value. */
	asm volatile("str %0, [%1]" : : "r"(0x90000000), "r"(CP15_TTBR0));
	val = 0xdeadbeef;
	assert(cp15_read(0, 2, 0, 0, &val));
	assert(val == 0x90000000);

	/* Now two regs at once: set TTBR1 to match TTBR0 */
	assert(cp15_write(0, 2, 0, 1, 0x90000000));
	
	val = 0xdeadbeef;
	asm volatile("ldr %0, [%1]" : "=r"(val) : "r"(CP15_TTBR0_TTBR1));
	/* Host checks that both match. */
	assert(val == 0x90000000);

	/* Now set both. */
	asm volatile("str %0, [%1]" : : "r"(0x80000000), "r"(CP15_TTBR0_TTBR1));
	assert(cp15_read(0, 2, 0, 0, &val));
	assert(val == 0x80000000);
	assert(cp15_read(0, 2, 0, 1, &val));
	assert(val == 0x80000000);

	return 0;
}
