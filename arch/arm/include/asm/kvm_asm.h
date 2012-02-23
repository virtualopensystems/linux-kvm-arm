/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 2, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 */

#ifndef __ARM_KVM_ASM_H__
#define __ARM_KVM_ASM_H__

#define ARM_EXCEPTION_RESET	  0
#define ARM_EXCEPTION_UNDEFINED   1
#define ARM_EXCEPTION_SOFTWARE    2
#define ARM_EXCEPTION_PREF_ABORT  3
#define ARM_EXCEPTION_DATA_ABORT  4
#define ARM_EXCEPTION_IRQ	  5
#define ARM_EXCEPTION_FIQ	  6
#define ARM_EXCEPTION_HVC	  7

/*
 * SMC Hypervisor API call number
 */
#define SMCHYP_HVBAR_W 0xfffffff0

#ifndef __ASSEMBLY__
struct kvm_vcpu;

extern char __kvm_hyp_init[];
extern char __kvm_hyp_init_end[];

extern char __kvm_hyp_vector[];
extern char __kvm_hyp_vector_end[];

extern char __kvm_hyp_code_start[];
extern char __kvm_hyp_code_end[];

extern void __kvm_flush_vm_context(void);

extern int __kvm_vcpu_run(struct kvm_vcpu *vcpu);
#endif

#endif /* __ARM_KVM_ASM_H__ */
