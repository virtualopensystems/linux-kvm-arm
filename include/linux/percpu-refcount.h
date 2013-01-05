#ifndef _LINUX_PERCPU_REFCOUNT_H
#define _LINUX_PERCPU_REFCOUNT_H

#include <linux/atomic.h>
#include <linux/percpu.h>

struct percpu_ref {
	atomic64_t		count;
	unsigned __percpu	*pcpu_count;
};

void percpu_ref_init(struct percpu_ref *ref);
void __percpu_ref_get(struct percpu_ref *ref, bool alloc);
int percpu_ref_put(struct percpu_ref *ref);

int percpu_ref_kill(struct percpu_ref *ref);
int percpu_ref_dead(struct percpu_ref *ref);

static inline void percpu_ref_get(struct percpu_ref *ref)
{
	__percpu_ref_get(ref, true);
}

static inline void percpu_ref_get_noalloc(struct percpu_ref *ref)
{
	__percpu_ref_get(ref, false);
}

#endif
