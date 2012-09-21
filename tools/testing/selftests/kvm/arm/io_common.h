#ifndef __IO_DATA_H
#define __IO_DATA_H

/* Report status of a test (0 == OK, other == fail) */
#define IO_CTL_STATUS	(0xf0000000)
/* exit with given error code (0 == OK, other == fail) */
#define IO_CTL_EXIT	(0xf0000001)
/* print a character */
#define IO_CTL_PRINT	(0xf0000002)
/* Stub MMIO operation, will cause a guest exit */
#define IO_CTL_STUB	(0xf0000003)

#endif /* __IO_DATA_H */
