#ifndef GUEST_H
#define GUEST_H

void ok(void);
void fail(void);
void putc(char c);
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

/* Each guest needs to write this. */
int test(void);
#endif /* GUEST_H */
