#define exit_reasons svm_exit_reasons
#define svm_exit_reasons 						\
	{SVM_EXIT_READ_CR0,           		"read_cr0"},		\
	{SVM_EXIT_READ_CR3,	      		"read_cr3"},		\
	{SVM_EXIT_READ_CR4,	      		"read_cr4"},		\
	{SVM_EXIT_READ_CR8,  	      		"read_cr8"},		\
	{SVM_EXIT_WRITE_CR0,          		"write_cr0"},		\
	{SVM_EXIT_WRITE_CR3,	      		"write_cr3"},		\
	{SVM_EXIT_WRITE_CR4,          		"write_cr4"},		\
	{SVM_EXIT_WRITE_CR8, 	      		"write_cr8"},		\
	{SVM_EXIT_READ_DR0, 	      		"read_dr0"},		\
	{SVM_EXIT_READ_DR1,	      		"read_dr1"},		\
	{SVM_EXIT_READ_DR2,	      		"read_dr2"},		\
	{SVM_EXIT_READ_DR3,	      		"read_dr3"},		\
	{SVM_EXIT_WRITE_DR0,	      		"write_dr0"},		\
	{SVM_EXIT_WRITE_DR1,	      		"write_dr1"},		\
	{SVM_EXIT_WRITE_DR2,	      		"write_dr2"},		\
	{SVM_EXIT_WRITE_DR3,	      		"write_dr3"},		\
	{SVM_EXIT_WRITE_DR5,	      		"write_dr5"},		\
	{SVM_EXIT_WRITE_DR7,	      		"write_dr7"},		\
	{SVM_EXIT_EXCP_BASE + DB_VECTOR,	"DB excp"},		\
	{SVM_EXIT_EXCP_BASE + BP_VECTOR,	"BP excp"},		\
	{SVM_EXIT_EXCP_BASE + UD_VECTOR,	"UD excp"},		\
	{SVM_EXIT_EXCP_BASE + PF_VECTOR,	"PF excp"},		\
	{SVM_EXIT_EXCP_BASE + NM_VECTOR,	"NM excp"},		\
	{SVM_EXIT_EXCP_BASE + MC_VECTOR,	"MC excp"},		\
	{SVM_EXIT_INTR,				"interrupt"},		\
	{SVM_EXIT_NMI,				"nmi"},			\
	{SVM_EXIT_SMI,				"smi"},			\
	{SVM_EXIT_INIT,				"init"},		\
	{SVM_EXIT_VINTR,			"vintr"},		\
	{SVM_EXIT_CPUID,			"cpuid"},		\
	{SVM_EXIT_INVD,				"invd"},		\
	{SVM_EXIT_HLT,				"hlt"},			\
	{SVM_EXIT_INVLPG,			"invlpg"},		\
	{SVM_EXIT_INVLPGA,			"invlpga"},		\
	{SVM_EXIT_IOIO,				"io"},			\
	{SVM_EXIT_MSR,				"msr"},			\
	{SVM_EXIT_TASK_SWITCH,			"task_switch"},		\
	{SVM_EXIT_SHUTDOWN,			"shutdown"},		\
	{SVM_EXIT_VMRUN,			"vmrun"},		\
	{SVM_EXIT_VMMCALL,			"hypercall"},		\
	{SVM_EXIT_VMLOAD,			"vmload"},		\
	{SVM_EXIT_VMSAVE,			"vmsave"},		\
	{SVM_EXIT_STGI,				"stgi"},		\
	{SVM_EXIT_CLGI,				"clgi"},		\
	{SVM_EXIT_SKINIT,			"skinit"},		\
	{SVM_EXIT_WBINVD,			"wbinvd"},		\
	{SVM_EXIT_MONITOR,			"monitor"},		\
	{SVM_EXIT_MWAIT,			"mwait"},		\
	{SVM_EXIT_NPF,				"npf"}
