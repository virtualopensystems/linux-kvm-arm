#if !defined(_TRACE_KVM_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_KVM_H

#include <linux/tracepoint.h>

#undef TRACE_SYSTEM
#define TRACE_SYSTEM kvm
#define TRACE_INCLUDE_PATH arch/x86/kvm
#define TRACE_INCLUDE_FILE trace

/*
 * Tracepoint for guest mode entry.
 */
TRACE_EVENT(kvm_entry,
	TP_PROTO(unsigned int vcpu_id),
	TP_ARGS(vcpu_id),

	TP_STRUCT__entry(
		__field(	unsigned int,	vcpu_id		)
	),

	TP_fast_assign(
		__entry->vcpu_id	= vcpu_id;
	),

	TP_printk("vcpu %u\n", __entry->vcpu_id)
);

/*
 * Tracepoint for hypercall.
 */
TRACE_EVENT(kvm_hypercall,
	TP_PROTO(unsigned long nr, unsigned long a0, unsigned long a1,
		 unsigned long a2, unsigned long a3),
	TP_ARGS(nr, a0, a1, a2, a3),

	TP_STRUCT__entry(
		__field(	unsigned long, 	nr		)
		__field(	unsigned long,	a0		)
		__field(	unsigned long,	a1		)
		__field(	unsigned long,	a2		)
		__field(	unsigned long,	a3		)
	),

	TP_fast_assign(
		__entry->nr		= nr;
		__entry->a0		= a0;
		__entry->a1		= a1;
		__entry->a2		= a2;
		__entry->a3		= a3;
	),

	TP_printk("nr 0x%lx a0 0x%lx a1 0x%lx a2 0x%lx a3 0x%lx",
		 __entry->nr, __entry->a0, __entry->a1,  __entry->a2,
		 __entry->a3)
);

/*
 * Tracepoint for PIO.
 */
TRACE_EVENT(kvm_pio,
	TP_PROTO(unsigned int rw, unsigned int port, unsigned int size,
		 unsigned int count),
	TP_ARGS(rw, port, size, count),

	TP_STRUCT__entry(
		__field(	unsigned int, 	rw		)
		__field(	unsigned int, 	port		)
		__field(	unsigned int, 	size		)
		__field(	unsigned int,	count		)
	),

	TP_fast_assign(
		__entry->rw		= rw;
		__entry->port		= port;
		__entry->size		= size;
		__entry->count		= count;
	),

	TP_printk("pio_%s at 0x%x size %d count %d",
		  __entry->rw ? "write" : "read",
		  __entry->port, __entry->size, __entry->count)
);

/*
 * Tracepoint for cpuid.
 */
TRACE_EVENT(kvm_cpuid,
	TP_PROTO(unsigned int function, unsigned long rax, unsigned long rbx,
		 unsigned long rcx, unsigned long rdx),
	TP_ARGS(function, rax, rbx, rcx, rdx),

	TP_STRUCT__entry(
		__field(	unsigned int,	function	)
		__field(	unsigned long,	rax		)
		__field(	unsigned long,	rbx		)
		__field(	unsigned long,	rcx		)
		__field(	unsigned long,	rdx		)
	),

	TP_fast_assign(
		__entry->function	= function;
		__entry->rax		= rax;
		__entry->rbx		= rbx;
		__entry->rcx		= rcx;
		__entry->rdx		= rdx;
	),

	TP_printk("func %x rax %lx rbx %lx rcx %lx rdx %lx",
		  __entry->function, __entry->rax,
		  __entry->rbx, __entry->rcx, __entry->rdx)
);

/*
 * Tracepoint for apic access.
 */
TRACE_EVENT(kvm_apic,
	TP_PROTO(unsigned int rw, unsigned int reg, unsigned int val),
	TP_ARGS(rw, reg, val),

	TP_STRUCT__entry(
		__field(	unsigned int,	rw		)
		__field(	unsigned int,	reg		)
		__field(	unsigned int,	val		)
	),

	TP_fast_assign(
		__entry->rw		= rw;
		__entry->reg		= reg;
		__entry->val		= val;
	),

	TP_printk("apic_%s 0x%x = 0x%x",
		  __entry->rw ? "write" : "read",
		  __entry->reg, __entry->val)
);

#define trace_kvm_apic_read(reg, val)		trace_kvm_apic(0, reg, val)
#define trace_kvm_apic_write(reg, val)		trace_kvm_apic(1, reg, val)

#endif /* _TRACE_KVM_H */

/* This part must be outside protection */
#include <trace/define_trace.h>
