#define exit_reasons vmx_exit_reasons
#define vmx_exit_reasons 						\
	{EXIT_REASON_EXCEPTION_NMI,           "exception"},		\
	{EXIT_REASON_EXTERNAL_INTERRUPT,      "ext_irq"},		\
	{EXIT_REASON_TRIPLE_FAULT,            "triple_fault"},		\
	{EXIT_REASON_NMI_WINDOW,              "nmi_window"},		\
	{EXIT_REASON_IO_INSTRUCTION,          "io_instruction"},	\
	{EXIT_REASON_CR_ACCESS,               "cr_access"},		\
	{EXIT_REASON_DR_ACCESS,               "dr_access"},		\
	{EXIT_REASON_CPUID,                   "cpuid"},			\
	{EXIT_REASON_MSR_READ,                "rdmsr"},			\
	{EXIT_REASON_MSR_WRITE,               "wrmsr"},			\
	{EXIT_REASON_PENDING_INTERRUPT,       "interrupt_window"},	\
	{EXIT_REASON_HLT,                     "halt"},			\
	{EXIT_REASON_INVLPG,                  "invlpg"},		\
	{EXIT_REASON_VMCALL,                  "hypercall"},		\
	{EXIT_REASON_TPR_BELOW_THRESHOLD,     "tpr_below_thres"},	\
	{EXIT_REASON_APIC_ACCESS,             "apic_access"},		\
	{EXIT_REASON_WBINVD,                  "wbinvd"},		\
	{EXIT_REASON_TASK_SWITCH,             "task_switch"},		\
	{EXIT_REASON_EPT_VIOLATION,           "ept_violation"}

