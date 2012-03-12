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

/* Architecturally implementation defined CP15 register access */
TRACE_EVENT(kvm_emulate_cp15_imp,
	TP_PROTO(unsigned long Op1, unsigned long Rt1, unsigned long CRn,
		 unsigned long CRm, unsigned long Op2, bool is_write),
	TP_ARGS(Op1, Rt1, CRn, CRm, Op2, is_write),

	TP_STRUCT__entry(
		__field(	unsigned int,	Op1		)
		__field(	unsigned int,	Rt1		)
		__field(	unsigned int,	CRn		)
		__field(	unsigned int,	CRm		)
		__field(	unsigned int,	Op2		)
		__field(	bool,		is_write	)
	),

	TP_fast_assign(
		__entry->is_write		= is_write;
		__entry->Op1			= Op1;
		__entry->Rt1			= Rt1;
		__entry->CRn			= CRn;
		__entry->CRm			= CRm;
		__entry->Op2			= Op2;
	),

	TP_printk("Implementation defined CP15: %s\tp15, %u, r%u, c%u, c%u, %u",
			(__entry->is_write) ? "mcr" : "mrc",
			__entry->Op1, __entry->Rt1, __entry->CRn,
			__entry->CRm, __entry->Op2)
);

#endif /* _TRACE_KVM_H */

#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH arch/arm/kvm
#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_FILE trace

/* This part must be outside protection */
#include <trace/define_trace.h>
