#if !defined(_TRACE_KVM_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_KVM_H

#include <linux/tracepoint.h>

#undef TRACE_SYSTEM
#define TRACE_SYSTEM kvm

/*
 * Tracepoints for entry/exit to guest
 */
TRACE_EVENT(kvm_entry,
	TP_PROTO(unsigned long vcpu_pc),
	TP_ARGS(vcpu_pc),

	TP_STRUCT__entry(
		__field(	unsigned long,	vcpu_pc		)
	),

	TP_fast_assign(
		__entry->vcpu_pc		= vcpu_pc;
	),

	TP_printk("PC: 0x%08lx", __entry->vcpu_pc)
);

TRACE_EVENT(kvm_exit,
	TP_PROTO(unsigned long vcpu_pc),
	TP_ARGS(vcpu_pc),

	TP_STRUCT__entry(
		__field(	unsigned long,	vcpu_pc		)
	),

	TP_fast_assign(
		__entry->vcpu_pc		= vcpu_pc;
	),

	TP_printk("PC: 0x%08lx", __entry->vcpu_pc)
);


TRACE_EVENT(kvm_irq_line,
	TP_PROTO(unsigned int type, unsigned int level, unsigned int vcpu_idx),
	TP_ARGS(type, level, vcpu_idx),

	TP_STRUCT__entry(
		__field(	unsigned int,	type			)
		__field(	unsigned int,	level			)
		__field(	unsigned int,	vcpu_idx		)
	),

	TP_fast_assign(
		__entry->type			= type;
		__entry->level			= level;
		__entry->vcpu_idx		= vcpu_idx;
	),

	TP_printk("KVM_IRQ_LINE: type: %s, level: %u, vcpu: %u",
		(__entry->type == KVM_ARM_IRQ_LINE) ? "IRQ" : "FIQ",
		__entry->level, __entry->vcpu_idx)
);


#endif /* _TRACE_KVM_H */

#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH arch/arm/kvm
#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_FILE trace

/* This part must be outside protection */
#include <trace/define_trace.h>
