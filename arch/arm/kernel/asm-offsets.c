/*
 * Copyright (C) 1995-2003 Russell King
 *               2001-2002 Keith Owens
 *     
 * Generate definitions needed by assembly language modules.
 * This code generates raw asm output which is post-processed to extract
 * and format the required data.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#include <linux/sched.h>
#include <linux/mm.h>
#include <asm/mach/arch.h>
#include <asm/thread_info.h>
#include <asm/memory.h>
#include <asm/procinfo.h>
#include <linux/kbuild.h>
#ifdef CONFIG_KVM
  #include <linux/kvm_host.h>
#endif

/*
 * Make sure that the compiler and target are compatible.
 */
#if defined(__APCS_26__)
#error Sorry, your compiler targets APCS-26 but this kernel requires APCS-32
#endif
/*
 * GCC 3.0, 3.1: general bad code generation.
 * GCC 3.2.0: incorrect function argument offset calculation.
 * GCC 3.2.x: miscompiles NEW_AUX_ENT in fs/binfmt_elf.c
 *            (http://gcc.gnu.org/PR8896) and incorrect structure
 *	      initialisation in fs/jffs2/erase.c
 */
#if (__GNUC__ == 3 && __GNUC_MINOR__ < 3)
#error Your compiler is too buggy; it is known to miscompile kernels.
#error    Known good compilers: 3.3
#endif

int main(void)
{
  DEFINE(TSK_ACTIVE_MM,		offsetof(struct task_struct, active_mm));
  DEFINE(TSK_FLAGS,		offsetof(struct task_struct, flags));
  BLANK();
  DEFINE(TI_FLAGS,		offsetof(struct thread_info, flags));
  DEFINE(TI_PREEMPT,		offsetof(struct thread_info, preempt_count));
  DEFINE(TI_ADDR_LIMIT,		offsetof(struct thread_info, addr_limit));
  DEFINE(TI_TASK,		offsetof(struct thread_info, task));
  DEFINE(TI_EXEC_DOMAIN,	offsetof(struct thread_info, exec_domain));
  DEFINE(TI_CPU,		offsetof(struct thread_info, cpu));
  DEFINE(TI_CPU_DOMAIN,		offsetof(struct thread_info, cpu_domain));
  DEFINE(TI_CPU_SAVE,		offsetof(struct thread_info, cpu_context));
  DEFINE(TI_USED_CP,		offsetof(struct thread_info, used_cp));
  DEFINE(TI_TP_VALUE,		offsetof(struct thread_info, tp_value));
  DEFINE(TI_FPSTATE,		offsetof(struct thread_info, fpstate));
  DEFINE(TI_VFPSTATE,		offsetof(struct thread_info, vfpstate));
#ifdef CONFIG_ARM_THUMBEE
  DEFINE(TI_THUMBEE_STATE,	offsetof(struct thread_info, thumbee_state));
#endif
#ifdef CONFIG_IWMMXT
  DEFINE(TI_IWMMXT_STATE,	offsetof(struct thread_info, fpstate.iwmmxt));
#endif
#ifdef CONFIG_CRUNCH
  DEFINE(TI_CRUNCH_STATE,	offsetof(struct thread_info, crunchstate));
#endif
  BLANK();
  DEFINE(S_R0,			offsetof(struct pt_regs, ARM_r0));
  DEFINE(S_R1,			offsetof(struct pt_regs, ARM_r1));
  DEFINE(S_R2,			offsetof(struct pt_regs, ARM_r2));
  DEFINE(S_R3,			offsetof(struct pt_regs, ARM_r3));
  DEFINE(S_R4,			offsetof(struct pt_regs, ARM_r4));
  DEFINE(S_R5,			offsetof(struct pt_regs, ARM_r5));
  DEFINE(S_R6,			offsetof(struct pt_regs, ARM_r6));
  DEFINE(S_R7,			offsetof(struct pt_regs, ARM_r7));
  DEFINE(S_R8,			offsetof(struct pt_regs, ARM_r8));
  DEFINE(S_R9,			offsetof(struct pt_regs, ARM_r9));
  DEFINE(S_R10,			offsetof(struct pt_regs, ARM_r10));
  DEFINE(S_FP,			offsetof(struct pt_regs, ARM_fp));
  DEFINE(S_IP,			offsetof(struct pt_regs, ARM_ip));
  DEFINE(S_SP,			offsetof(struct pt_regs, ARM_sp));
  DEFINE(S_LR,			offsetof(struct pt_regs, ARM_lr));
  DEFINE(S_PC,			offsetof(struct pt_regs, ARM_pc));
  DEFINE(S_PSR,			offsetof(struct pt_regs, ARM_cpsr));
  DEFINE(S_OLD_R0,		offsetof(struct pt_regs, ARM_ORIG_r0));
  DEFINE(S_FRAME_SIZE,		sizeof(struct pt_regs));
  BLANK();
#ifdef CONFIG_CPU_HAS_ASID
  DEFINE(MM_CONTEXT_ID,		offsetof(struct mm_struct, context.id));
  BLANK();
#endif
  DEFINE(VMA_VM_MM,		offsetof(struct vm_area_struct, vm_mm));
  DEFINE(VMA_VM_FLAGS,		offsetof(struct vm_area_struct, vm_flags));
  BLANK();
  DEFINE(VM_EXEC,	       	VM_EXEC); 
  BLANK();
  DEFINE(PAGE_SZ,	       	PAGE_SIZE);
  BLANK();
  DEFINE(SYS_ERROR0,		0x9f0000);
  BLANK();
  DEFINE(SIZEOF_MACHINE_DESC,	sizeof(struct machine_desc));
  DEFINE(MACHINFO_TYPE,		offsetof(struct machine_desc, nr));
  DEFINE(MACHINFO_NAME,		offsetof(struct machine_desc, name));
  DEFINE(MACHINFO_PHYSIO,	offsetof(struct machine_desc, phys_io));
  DEFINE(MACHINFO_PGOFFIO,	offsetof(struct machine_desc, io_pg_offst));
  BLANK();
  DEFINE(PROC_INFO_SZ,		sizeof(struct proc_info_list));
  DEFINE(PROCINFO_INITFUNC,	offsetof(struct proc_info_list, __cpu_flush));
  DEFINE(PROCINFO_MM_MMUFLAGS,	offsetof(struct proc_info_list, __cpu_mm_mmu_flags));
  DEFINE(PROCINFO_IO_MMUFLAGS,	offsetof(struct proc_info_list, __cpu_io_mmu_flags));
  BLANK();
#ifdef MULTI_DABORT
  DEFINE(PROCESSOR_DABT_FUNC,	offsetof(struct processor, _data_abort));
#endif
#ifdef MULTI_PABORT
  DEFINE(PROCESSOR_PABT_FUNC,	offsetof(struct processor, _prefetch_abort));
#endif

#ifdef CONFIG_KVM
  DEFINE(VCPU_HOST_PGD_PA,      offsetof(struct kvm_vcpu, arch.host_pgd_pa));
  DEFINE(VCPU_HOST_FAR,         offsetof(struct kvm_vcpu, arch.host_far));
  DEFINE(VCPU_HOST_FSR,         offsetof(struct kvm_vcpu, arch.host_fsr));
  DEFINE(VCPU_HOST_IFSR,        offsetof(struct kvm_vcpu, arch.host_ifsr));
  DEFINE(VCPU_HOST_VEC_HIGH,    offsetof(struct kvm_vcpu, arch.host_vectors_high));
  DEFINE(VCPU_EXCP_IDX,    	offsetof(struct kvm_vcpu, arch.guest_exception));

  DEFINE(SIZEOF_SHARED_STRUCT,  sizeof(struct shared_page));
  DEFINE(SHARED_SHARED_SP,      offsetof(struct shared_page, shared_sp));
  DEFINE(SHARED_RET_PTR,        offsetof(struct shared_page, return_ptr));
  DEFINE(SHARED_IRQ_SVC_ADDR,   offsetof(struct shared_page, irq_svc_address));
  DEFINE(SHARED_HOST_SP,        offsetof(struct shared_page, host_sp));
  DEFINE(SHARED_EXCEPTION_IDX,  offsetof(struct shared_page, exception_index));
  DEFINE(SHARED_HOST_REGS,      offsetof(struct shared_page, host_regs));
  DEFINE(SHARED_HOST_CPSR,      offsetof(struct shared_page, host_CPSR));
  DEFINE(SHARED_HOST_SPSR,      offsetof(struct shared_page, host_SPSR));
  DEFINE(SHARED_HOST_TTBR,      offsetof(struct shared_page, host_ttbr));
  DEFINE(SHARED_SHADOW_TTBR,    offsetof(struct shared_page, shadow_ttbr));
  DEFINE(SHARED_EXEC_CPSR,	offsetof(struct shared_page, execution_CPSR));
  DEFINE(SHARED_GUEST_DAC,      offsetof(struct shared_page, guest_dac));
  DEFINE(SHARED_GUEST_ASID,     offsetof(struct shared_page, guest_asid));
  DEFINE(SHARED_HOST_DAC,       offsetof(struct shared_page, host_dac));
  DEFINE(SHARED_HOST_ASID,      offsetof(struct shared_page, host_asid));
  DEFINE(SHARED_GUEST_INSTR,    offsetof(struct shared_page, guest_instr));
  DEFINE(SHARED_ORIG_INSTR,     offsetof(struct shared_page, orig_instr));
  DEFINE(SHARED_VCPU_MODE,	offsetof(struct shared_page, vcpu_mode));
  DEFINE(SHARED_VCPU_REGS,	offsetof(struct shared_page, vcpu_regs));
  DEFINE(SHARED_FULL_FLUSH,	offsetof(struct shared_page, full_flush_mode));

  DEFINE(VCPU_REGS_FIQ,		offsetof(struct kvm_vcpu_regs, fiq_reg));
  DEFINE(VCPU_REGS_USR,		offsetof(struct kvm_vcpu_regs, usr_reg));
  DEFINE(VCPU_REGS_BANKED_FIQ,	offsetof(struct kvm_vcpu_regs, banked_fiq));
  DEFINE(VCPU_REGS_SHARED_REG,	offsetof(struct kvm_vcpu_regs, shared_reg));
  DEFINE(VCPU_REGS_R15,		offsetof(struct kvm_vcpu_regs, r15));
#endif

  return 0; 
}
