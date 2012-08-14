#ifndef __GUEST_DRIVER_H_
#define __GUEST_DRIVER_H_

#define PAGE_SIZE (4096)
#define PAGE_MASK (~(PAGE_SIZE - 1))
#define EXIT_SETUPFAIL 2

#define CODE_SLOT 0
#define CODE_PHYS_BASE (0x80000000)
#define RAM_SIZE (1024 * PAGE_SIZE) /* 1 MB of physical RAM , yeah! */

struct kvm_run;
struct test {
	const char *name;
	const char *binname;
	bool (*mmiofn)(struct kvm_run *kvm_run);
};

#define stringify(expr)		stringify_1(expr)
/* Double-indirection required to stringify expansions */
#define stringify_1(expr)	#expr

#define GUEST_TEST(name, testfn)					\
	struct test test_##name __attribute__((section("tests"))) = {	\
		stringify(name), stringify(name) "-guest", testfn }

#endif /* __GUEST_DRIVER_H_ */
