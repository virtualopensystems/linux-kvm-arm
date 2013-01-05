#define pr_fmt(fmt) "%s: " fmt "\n", __func__

#include <linux/kernel.h>
#include <linux/jiffies.h>
#include <linux/percpu-refcount.h>
#include <linux/rcupdate.h>

#define PCPU_COUNT_BITS		50
#define PCPU_COUNT_MASK		((1LL << PCPU_COUNT_BITS) - 1)

#define PCPU_STATUS_BITS	2
#define PCPU_STATUS_MASK	((1 << PCPU_STATUS_BITS) - 1)

#define PCPU_REF_PTR		0
#define PCPU_REF_NONE		1
#define PCPU_REF_DYING		2
#define PCPU_REF_DEAD		3

#define REF_STATUS(count)	((unsigned long) count & PCPU_STATUS_MASK)

void percpu_ref_init(struct percpu_ref *ref)
{
	unsigned long now = jiffies;

	atomic64_set(&ref->count, 1);

	now <<= PCPU_STATUS_BITS;
	now |= PCPU_REF_NONE;

	ref->pcpu_count = (void *) now;
}

static void percpu_ref_alloc(struct percpu_ref *ref, unsigned __user *pcpu_count)
{
	unsigned __percpu *new;
	unsigned long last = (unsigned long) pcpu_count;
	unsigned long now = jiffies;

	now <<= PCPU_STATUS_BITS;
	now |= PCPU_REF_NONE;

	if (now - last <= HZ << PCPU_STATUS_BITS) {
		rcu_read_unlock();
		new = alloc_percpu(unsigned);
		rcu_read_lock();

		if (!new)
			goto update_time;

		BUG_ON(((unsigned long) new) & PCPU_STATUS_MASK);

		if (cmpxchg(&ref->pcpu_count, pcpu_count, new) != pcpu_count)
			free_percpu(new);
		else
			pr_debug("created");
	} else {
update_time:	new = (void *) now;
		cmpxchg(&ref->pcpu_count, pcpu_count, new);
	}
}

void __percpu_ref_get(struct percpu_ref *ref, bool alloc)
{
	unsigned __percpu *pcpu_count;
	uint64_t v;

	pcpu_count = rcu_dereference(ref->pcpu_count);

	if (REF_STATUS(pcpu_count) == PCPU_REF_PTR) {
		__this_cpu_inc(*pcpu_count);
	} else {
		v = atomic64_add_return(1 + (1ULL << PCPU_COUNT_BITS),
					&ref->count);

		if (!(v >> PCPU_COUNT_BITS) &&
		    REF_STATUS(pcpu_count) == PCPU_REF_NONE && alloc)
			percpu_ref_alloc(ref, pcpu_count);
	}
}

int percpu_ref_put(struct percpu_ref *ref)
{
	unsigned __percpu *pcpu_count;
	uint64_t v;
	int ret = 0;

	rcu_read_lock();

	pcpu_count = rcu_dereference(ref->pcpu_count);

	switch (REF_STATUS(pcpu_count)) {
	case PCPU_REF_PTR:
		__this_cpu_dec(*pcpu_count);
		break;
	case PCPU_REF_NONE:
	case PCPU_REF_DYING:
		atomic64_dec(&ref->count);
		break;
	case PCPU_REF_DEAD:
		v = atomic64_dec_return(&ref->count);
		v &= PCPU_COUNT_MASK;

		ret = v == 0;
		break;
	}

	rcu_read_unlock();

	return ret;
}

int percpu_ref_kill(struct percpu_ref *ref)
{
	unsigned __percpu *old, *new, *pcpu_count = ref->pcpu_count;
	unsigned long status;

	do {
		status = REF_STATUS(pcpu_count);

		switch (status) {
		case PCPU_REF_PTR:
			new = (void *) PCPU_REF_DYING;
			break;
		case PCPU_REF_NONE:
			new = (void *) PCPU_REF_DEAD;
			break;
		case PCPU_REF_DYING:
		case PCPU_REF_DEAD:
			return 0;
		}

		old = pcpu_count;
		pcpu_count = cmpxchg(&ref->pcpu_count, old, new);
	} while (pcpu_count != old);

	if (status == PCPU_REF_PTR) {
		unsigned count = 0, cpu;

		synchronize_rcu();

		for_each_possible_cpu(cpu)
			count += *per_cpu_ptr(pcpu_count, cpu);

		pr_debug("global %lli pcpu %i",
			 atomic64_read(&ref->count) & PCPU_COUNT_MASK,
			 (int) count);

		atomic64_add((int) count, &ref->count);
		smp_wmb();
		/* Between setting global count and setting PCPU_REF_DEAD */
		ref->pcpu_count = (void *) PCPU_REF_DEAD;

		free_percpu(pcpu_count);
	}

	return 1;
}

int percpu_ref_dead(struct percpu_ref *ref)
{
	unsigned status = REF_STATUS(ref->pcpu_count);

	return status == PCPU_REF_DYING ||
		status == PCPU_REF_DEAD;
}
