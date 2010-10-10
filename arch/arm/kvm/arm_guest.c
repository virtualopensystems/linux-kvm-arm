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

#include <linux/errno.h>
#include <linux/err.h>
#include <linux/kvm_host.h>
#include <linux/module.h>
#include <linux/vmalloc.h>
#include <linux/fs.h>
#include <asm/uaccess.h>
#include <asm/kvm_arm.h>


#define VM_STAT(x) offsetof(struct kvm, stat.x), KVM_STAT_VM
#define VCPU_STAT(x) offsetof(struct kvm_vcpu, stat.x), KVM_STAT_VCPU

struct kvm_stats_debugfs_item debugfs_entries[] = {
};  

int kvm_arch_vcpu_setup(struct kvm_vcpu *vcpu)
{
	return 0;
}

int kvm_arch_vcpu_ioctl_get_regs(struct kvm_vcpu *vcpu, struct kvm_regs *regs)
{
	/*
	 * GPRs and PSRs
	 */
	memcpy(regs->regs0_7, vcpu->arch.regs, sizeof(u32) * 8);
	memcpy(regs->usr_regs8_12, vcpu->arch.regs, sizeof(u32) * 5);
	memcpy(regs->fiq_regs8_12, vcpu->arch.fiq_regs, sizeof(u32) * 5);
	memcpy(regs->reg13, vcpu->arch.banked_r13, sizeof(u32) * 5);
	memcpy(regs->reg14, vcpu->arch.banked_r14, sizeof(u32) * 5);
	regs->reg15 = vcpu->arch.regs[15];
	regs->cpsr = vcpu->arch.cpsr;
	memcpy(regs->spsr, vcpu->arch.banked_spsr, sizeof(u32) * 5);

	/*
	 * Co-processor registers.
	 */
	regs->cp15.c0_cpuid = vcpu->arch.cp15.c0_MIDR;
	regs->cp15.c2_base0 = vcpu->arch.cp15.c2_TTBR0;
	regs->cp15.c2_base1 = vcpu->arch.cp15.c2_TTBR1;
	regs->cp15.c3 = vcpu->arch.cp15.c3_DACR;

	return 0;
}

int kvm_arch_vcpu_ioctl_set_regs(struct kvm_vcpu *vcpu, struct kvm_regs *regs)
{
	memcpy(vcpu->arch.regs, regs->regs0_7, sizeof(u32) * 8);
	memcpy(vcpu->arch.regs, regs->usr_regs8_12, sizeof(u32) * 5);
	memcpy(vcpu->arch.fiq_regs, regs->fiq_regs8_12, sizeof(u32) * 5);
	memcpy(vcpu->arch.banked_r13, regs->reg13, sizeof(u32) * 5);
	memcpy(vcpu->arch.banked_r14, regs->reg14, sizeof(u32) * 5);
	vcpu->arch.regs[15] = regs->reg15;
	kvm_cpsr_write(vcpu, regs->cpsr);
	memcpy(vcpu->arch.banked_spsr, regs->spsr, sizeof(u32) * 5);

	/*
	 * Co-processor registers.
	 */
	//vcpu->arch.cp15.c0_MIDR = regs->cp15.c0_cpuid;

	return 0;
}

int kvm_arch_vcpu_ioctl_get_sregs(struct kvm_vcpu *vcpu,
                                  struct kvm_sregs *sregs)
{
	return -ENOTSUPP;
}

int kvm_arch_vcpu_ioctl_set_sregs(struct kvm_vcpu *vcpu,
                                  struct kvm_sregs *sregs)
{
	return -ENOTSUPP;
}

int kvm_arch_vcpu_ioctl_get_fpu(struct kvm_vcpu *vcpu, struct kvm_fpu *fpu)
{
	return -ENOTSUPP;
}

int kvm_arch_vcpu_ioctl_set_fpu(struct kvm_vcpu *vcpu, struct kvm_fpu *fpu)
{
	return -ENOTSUPP;
}

/* 'linear_address' is actually an encoding of AS|PID|EADDR . */
int kvm_arch_vcpu_ioctl_translate(struct kvm_vcpu *vcpu,
                                  struct kvm_translation *tr)
{
	return 0;
}
