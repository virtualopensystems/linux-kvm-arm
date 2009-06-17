#if !defined(_TRACE_KVM_ARCH_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_KVM_ARCH_H

#include <linux/tracepoint.h>

#undef TRACE_SYSTEM
#define TRACE_SYSTEM kvm
#define TRACE_INCLUDE_PATH arch/x86/kvm
#define TRACE_INCLUDE_FILE trace-arch

/*
 * Tracepoint for kvm guest exit:
 */
TRACE_EVENT(kvm_exit,
	TP_PROTO(unsigned int exit_reason, unsigned long guest_rip),
	TP_ARGS(exit_reason, guest_rip),

	TP_STRUCT__entry(
		__field(	unsigned int,	exit_reason	)
		__field(	unsigned long,	guest_rip	)
	),

	TP_fast_assign(
		__entry->exit_reason	= exit_reason;
		__entry->guest_rip	= guest_rip;
	),

	TP_printk("reason %s rip 0x%lx",
		  __print_symbolic(__entry->exit_reason, exit_reasons),
		 __entry->guest_rip)
);

/*
 * Tracepoint for kvm interrupt injection:
 */
TRACE_EVENT(kvm_inj_virq,
	TP_PROTO(unsigned int irq),
	TP_ARGS(irq),

	TP_STRUCT__entry(
		__field(	unsigned int,	irq		)
	),

	TP_fast_assign(
		__entry->irq		= irq;
	),

	TP_printk("irq %u", __entry->irq)
);

/*
 * Tracepoint for page fault.
 */
TRACE_EVENT(kvm_page_fault,
	TP_PROTO(unsigned long fault_address, unsigned int error_code),
	TP_ARGS(fault_address, error_code),

	TP_STRUCT__entry(
		__field(	unsigned long,	fault_address	)
		__field(	unsigned int,	error_code	)
	),

	TP_fast_assign(
		__entry->fault_address	= fault_address;
		__entry->error_code	= error_code;
	),

	TP_printk("address %lx error_code %x",
		  __entry->fault_address, __entry->error_code)
);

/*
 * Tracepoint for guest MSR access.
 */
TRACE_EVENT(kvm_msr,
	TP_PROTO(unsigned int rw, unsigned int ecx, unsigned long data),
	TP_ARGS(rw, ecx, data),

	TP_STRUCT__entry(
		__field(	unsigned int,	rw		)
		__field(	unsigned int,	ecx		)
		__field(	unsigned long,	data		)
	),

	TP_fast_assign(
		__entry->rw		= rw;
		__entry->ecx		= ecx;
		__entry->data		= data;
	),

	TP_printk("msr_%s %x = 0x%lx",
		  __entry->rw ? "write" : "read",
		  __entry->ecx, __entry->data)
);

#define trace_kvm_msr_read(ecx, data)		trace_kvm_msr(0, ecx, data)
#define trace_kvm_msr_write(ecx, data)		trace_kvm_msr(1, ecx, data)

/*
 * Tracepoint for guest CR access.
 */
TRACE_EVENT(kvm_cr,
	TP_PROTO(unsigned int rw, unsigned int cr, unsigned long val),
	TP_ARGS(rw, cr, val),

	TP_STRUCT__entry(
		__field(	unsigned int,	rw		)
		__field(	unsigned int,	cr		)
		__field(	unsigned long,	val		)
	),

	TP_fast_assign(
		__entry->rw		= rw;
		__entry->cr		= cr;
		__entry->val		= val;
	),

	TP_printk("cr_%s %x = 0x%lx",
		  __entry->rw ? "write" : "read",
		  __entry->cr, __entry->val)
);

#define trace_kvm_cr_read(cr, val)		trace_kvm_cr(0, cr, val)
#define trace_kvm_cr_write(cr, val)		trace_kvm_cr(1, cr, val)

#endif /* _TRACE_KVM_ARCH_H */

/* This part must be outside protection */
#include <trace/define_trace.h>
