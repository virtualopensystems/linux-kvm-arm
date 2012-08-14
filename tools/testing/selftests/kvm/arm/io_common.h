#ifndef __IO_DATA_H
#define __IO_DATA_H

#define IO_DATA_BASE (0xc0000000)
#define IO_DATA "123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyziThe quick brown fox jumps over the lazy dog"

#define IO_CTL_BASE (0xf0000000)
#define IO_DATA_SIZE (1)
#define CTL_OK		0
#define CTL_FAIL	1
#define CTL_ERR		2
#define CTL_DONE	3

#endif /* __IO_DATA_H */
