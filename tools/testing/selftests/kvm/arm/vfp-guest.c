#include "guest.h"
#include "vfp_test.h"

#define FPEXC_EN		(1 << 30)

static int get_fpexc(void)
{
	int fpexc;

	asm("mrc p10, 7, %0, cr8, cr0, 0" : "=r"(fpexc));
	return fpexc;
}

static void set_fpexc(int fpexc)
{
	asm("mcr p10, 7, %0, cr8, cr0, 0" : : "r"(fpexc));
}

static void turn_on_coproc_access(void)
{
	int cpacr;

	asm volatile("mrc p15, 0, %0, c1, c0, 2" : "=r" (cpacr));

	/* VFP is coprocessors 10 and 11: both bits means all accessible. */
	cpacr |= (0xF << 20);

	asm volatile("mcr p15, 0, %0, c1, c0, 2" : : "r" (cpacr));
}

int test(void)
{
	register double d0 asm("d0");
	register double d1 asm("d1");
	register double d2 asm("d2");
	register double d3 asm("d3");
	register double d16 asm("d16");
	register double d17 asm("d17");
	register double d18 asm("d18");
	register double d19 asm("d19");
	int val;
	int i;

	print("Turning on CP10/11 access\n");
	turn_on_coproc_access();

	print("Getting FP\n");
	val = get_fpexc();
	assert(!(val & FPEXC_EN));

	print("Enabling FP\n");
	set_fpexc(get_fpexc() | FPEXC_EN);

	print("Basic floating point test\n");
	d1 = 1.0 / 8;
	vm_exit();
	d2 = 1.0 / 16;
	vm_exit();
	d3 = d1 + d2;
	vm_exit();
	assert(d3 == 3.0 / 16);

	/* Now, try loading 2.0 and make sure host doesn't interfere! */
	d0 = 2.0;
	assert(d0 == 2.0);
	read(VFP_USE_REG, val);
	assert(d0 == 2.0);

	/* Same thing with upper 16 registers. */
	d17 = 1.0 / 8;
	vm_exit();
	d18 = 1.0 / 16;
	vm_exit();
	d19 = d17 + d18;
	vm_exit();
	assert(d19 == 3.0 / 16);

	d16 = 2.0;
	assert(d16 == 2.0);
	read(VFP_USE_REG + 16, val);
	assert(d16 == 2.0);

	/* Now check host ioctl sees register correctly. */
	d0 = 2.0;
	read(VFP_CHECK_REG, val);

	d0 = 2.0;
	read(VFP_SET_REG, val);
	assert(d0 == 3.0);

	d16 = 2.0;
	read(VFP_CHECK_REG + 16, val);

	d16 = 2.0;
	read(VFP_SET_REG + 16, val);
	assert(d16 == 3.0);

	/* Check again a high number of exits doesn't affect results */
	d0 = 100.0;
	d1 = 1.073;
	d16 = d0;
	d17 = d1;

	for(i = 0; i < 1000; i++)
		d0 *= d1;

	for(i = 0; i < 1000; i++) {
		vm_exit();
		d16 *= d17;
		vm_exit();
	}

	assert(d0 == d16);

	return 0;
}
