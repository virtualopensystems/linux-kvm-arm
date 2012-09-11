#ifndef VFP_TEST_H
#define VFP_TEST_H

/* This uses reg in host, to check for interference. */
#define VFP_USE_REG (0xc0000000) /* + offset of register number */
/* This uses ioctl to check register is 2.0. */
#define VFP_CHECK_REG (0xc0000020) /* + offset of register number */
/* This uses ioctl to set register to 3.0. */
#define VFP_SET_REG (0xc0000040) /* + offset of register number */

#endif /* VFP_TEST_H */
