#include "guest.h"
#include "guest-util.h"
#include "mmio_test.h"
#include "vmexit.h"

__asm__(".arch_extension	virt");

//#define DEBUG 1

#define GOAL (1ULL << 28)

#define ARR_SIZE(_x) ((sizeof(_x) / sizeof(_x[0])))

static unsigned long vgic_base;

#if 0
typedef unsigned long long u64;

static u64 pgd[4] __attribute__ ((aligned (32)));

#define PGD_SHIFT 30
#define PGD_SIZE (1 << PGD_SHIFT)
#define PGD_AF   (1 << 10) /* Don't raise access flag exceptions */
#define PGD_SH	 (3 << 8) /* All memory inner+outer shareable */

static void enable_mmu(void)
{
	unsigned long long i;

	/* Set up an identitify mapping */
	for (i = 0; i < 4; i++) {
		pgd[i] = (i * PGD_SIZE);
		pgd[i] |= PGD_AF | PGD_SH

	}
}
#endif

static unsigned long read_cc(void)
{
	unsigned long cc;
	asm volatile("mrc p15, 0, %[reg], c9, c13, 0": [reg] "=r" (cc));
	return cc;
}

static void hvc_test(void)
{
	asm volatile("hvc #0");
}

static void mmio_vgic_init(void)
{
	vgic_base = VGIC_DIST_BASE;
}

static void mmio_vgic_test(void)
{
	(void)readl(vgic_base);
}

static void mmio_fake_test(void)
{
	(void)readl(FAKE_MMIO);
}

struct exit_test {
	char *name;
	void (*test_fn)(void);
	void (*init_fn)(void);
};

static void loop_test(struct exit_test *test)
{
	unsigned long i, iterations = 32;
	unsigned long c2, c1, cycles = 0;

	do {
		iterations *= 2;

		c1 = read_cc();
		for (i = 0; i < iterations; i++)
			test->test_fn();
		c2 = read_cc();

		if (c1 >= c2)
			continue;
		cycles = c2 - c1;
	} while (cycles < GOAL);

#if DEBUG
	printf("%s exit %u cycles over %u iterations = %u\n",
	       test->name, cycles, iterations, cycles / iterations);
#else
	printf("%s\t%u\n",
	       test->name, cycles / iterations);
#endif
}

static struct exit_test available_tests[] = {
	{ "hvc",		hvc_test,		NULL		},
	{ "vgic_mmio",		mmio_vgic_test,		mmio_vgic_init	},
	{ "fake_mmio",		mmio_fake_test,		NULL		},
};

int test(void)
{
	unsigned int i;
	struct exit_test *test;

	for (i = 0; i < ARR_SIZE(available_tests); i++) {
		test = &available_tests[i];
		if (test->init_fn)
			test->init_fn();
		loop_test(test);
	}

	return 0;
}
