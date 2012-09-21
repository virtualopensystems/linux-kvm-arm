#ifndef GUEST_H
#define GUEST_H
#include <stdint.h>
#include <stdbool.h>

void ok(void);
void fail(void);
void putc(char c);
void vm_exit(void);
extern int skip_undef, undef_count;

static inline void print(const char *p)
{
	while (*p)
		putc(*(p++));
}

#define stringify(expr)		stringify_1(expr)
/* Double-indirection required to stringify expansions */
#define stringify_1(expr)	#expr

#define assert(cond)							\
	do {								\
		if (!(cond)) {						\
			print(__FILE__ ":" stringify(__LINE__) ":"	\
			      stringify(cond) ": FAILED\n");		\
			fail();						\
		} else							\
			ok();						\
	} while(0)

/* Handy MMIO read/write macros since we use those a lot */
#define read(token, val) \
	asm volatile("ldr %0, [%1]" : "=r"(val) : "r"(token));
#define write(token, val) \
	asm volatile("str %0, [%1]" : : "r"(val), "r"(token));

typedef uint32_t u32;

/* Each guest needs to write this. */
int test(void);
#endif /* GUEST_H */
