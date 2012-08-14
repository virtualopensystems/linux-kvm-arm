#include "guest.h"
#include "mmio_test.h"

int test(void)
{
	register int r1 asm("r1");
	register int r2 asm("r2");
	register int r3 asm("r3");

	print("Perform a simple load test\n");
	asm volatile("ldr %0, [%1]" : "=r"(r1) : "r"(IO_DATA_BASE));
	assert(r1 == *(int *)IO_DATA);

	print("Perform a simple write test\n");
	r1 = *(int *)IO_DATA;
	asm volatile("str %0, [%1]" : : "r"(r1), "r"(IO_DATA_BASE));
	ok();

	print("Perform a load-multiple load test\n");
	asm volatile("ldmia %3, { %0, %1, %2 }\n"
		     : "=r"(r1), "=r"(r2), "=r"(r3)
		     : "r"(IO_DATA_BASE));
	assert(r1 == ((int *)IO_DATA)[0]
	       && r2 == ((int *)IO_DATA)[1]
	       && r2 == ((int *)IO_DATA)[2]);

	return 0;
}
