#include "guest.h"
#include "mmio_test.h"

static char *io_data = IO_DATA;

int test(void)
{
	register int r1 asm("r1");
	register int r2 asm("r2");
	register int r3 asm("r3");

	print("Perform a simple load test\n");
	asm volatile("ldr %0, [%1]" : "=r"(r1) : "r"(IO_DATA_BASE));
	assert(r1 == *(int *)io_data);

	print("Perform a simple write test\n");
	r1 = *(int *)IO_DATA;
	asm volatile("str %0, [%1]" : : "r"(r1), "r"(IO_DATA_BASE));
	ok();

	return 0;
}
