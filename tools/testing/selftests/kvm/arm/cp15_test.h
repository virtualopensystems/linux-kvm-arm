#ifndef CP15_TEST_H
#define CP15_TEST_H

/* Make host set/get TTBR0 */
#define CP15_TTBR0		(0xc0000000)

/* Make host set/get TTBR0 and TTBR1, atomically. */
#define CP15_TTBR0_TTBR1	(0xc0000004)

#endif /* CP15_TEST_H */
