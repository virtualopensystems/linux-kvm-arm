/* Test that false conditional traps don't get executed.  Platform may not
 * even trap, but if it does, hypervisor should check condition and not
 * execute if it's false.  */
#include "guest.h"
#include "io_common.h"

int test(void)
{
	int ioaddr, val;

	print("This code should not trap\n");

	ioaddr = IO_CTL_STATUS;
	/* 1 == fail (should not execute). */
	asm volatile("movs	%0, $1\n\t"
		     "streqb	%0, [%1]" : "=r"(val) : "r"(ioaddr));
	ok();

	print("This code should trap\n");
	/* 0 == ok (should execute). */
	asm volatile("movs	%0, $0\n\t"
		     "streqb	%0, [%1]" : "=r"(val) : "r"(ioaddr));

#if 0 /* FIXME: Make this work! */
	/* Thumb mode, should not call fail. */
	asm volatile("bx	=thumbtest1\n\t"
		     ".thumb\n"
		     "thumbtest1:\n\t"
		     "movs	%0, $1\n\t"
		     "it	eq\n\t"
		     "streqb	%0, [%1]\n\t"
		     "bx	=endtest1\n\t"
		     ".arm\n"
		     "endtest1:" : "=r"(val) : "r"(ioaddr));
	ok();

	/* Thumb mode, should call be executed. */
	asm volatile("bx	=thumbtest2\n\t"
		     ".thumb\n"
		     "thumbtest2:\n\t"
		     "movs	%0, $0\n\t"
		     "it	eq\n\t"
		     "streqb	%0, [%1]\n\t"
		     "bx	=endtest2\n\t"
		     ".arm\n"
		     "endtest2:"  : "=r"(val) : "r"(ioaddr));
#endif

	return 0;
}
