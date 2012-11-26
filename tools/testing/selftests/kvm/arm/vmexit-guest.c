#include "guest.h"
#include "guest-util.h"
#include "mmio_test.h"

__asm__(".arch_extension	virt");

#define GOAL (1ULL << 30)

static unsigned long read_cc(void)
{
	unsigned long cc;
	asm volatile("mrc p15, 0, %[reg], c9, c13, 0": [reg] "=r" (cc));
	return cc;
}

static void hvc_exit(void)
{
	unsigned long i, iterations = 32;
	unsigned long c2, c1, cycles;

	do {
		iterations *= 2;

		c1 = read_cc();
		for (i = 0; i < iterations; i++)
			asm volatile("hvc #0");
		c2 = read_cc();

		if (c1 >= c2)
			continue;
		cycles = c2 - c1;
	} while (cycles < GOAL);

	printf("hvc exit %u cycles over %u iterations = %u\n",
	       cycles, iterations, cycles / iterations);
}

int test(void)
{
	hvc_exit();
	return 0;
}
