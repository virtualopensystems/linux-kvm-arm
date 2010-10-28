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
	struct kvm_vcpu_regs *vcpu_regs = vcpu->arch.regs;

	/*
	 * GPRs and PSRs
	 */
	memcpy(regs->regs0_7, &(vcpu_regs->shared_reg[0]), sizeof(u32) * 8);
	memcpy(regs->usr_regs8_12, &(vcpu_regs->usr_reg[0]), sizeof(u32) * 5);
	memcpy(regs->fiq_regs8_12, &(vcpu_regs->fiq_reg[0]), sizeof(u32) * 5);
	regs->reg13[MODE_FIQ]   = vcpu_regs->banked_fiq[0];
	regs->reg14[MODE_FIQ]   = vcpu_regs->banked_fiq[1];
	regs->reg13[MODE_IRQ]   = vcpu_regs->banked_irq[0];
	regs->reg14[MODE_IRQ]   = vcpu_regs->banked_irq[1];
	regs->reg13[MODE_SVC]   = vcpu_regs->banked_svc[0];
	regs->reg14[MODE_SVC]   = vcpu_regs->banked_svc[1];
	regs->reg13[MODE_ABORT] = vcpu_regs->banked_abt[0];
	regs->reg14[MODE_ABORT] = vcpu_regs->banked_abt[1];
	regs->reg13[MODE_UNDEF] = vcpu_regs->banked_und[0];
	regs->reg14[MODE_UNDEF] = vcpu_regs->banked_und[1];
	regs->reg13[MODE_USER]  = vcpu_regs->banked_usr[0];
	regs->reg14[MODE_USER]  = vcpu_regs->banked_usr[1];
	regs->reg15 = vcpu_reg(vcpu, 15);
	regs->cpsr = vcpu_regs->cpsr;
	memcpy(regs->spsr, vcpu_regs->spsr, sizeof(u32) * 5);

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
	struct kvm_vcpu_regs *vcpu_regs = vcpu->arch.regs;

	memcpy(&(vcpu_regs->shared_reg[0]), regs->regs0_7, sizeof(u32) * 8);
	memcpy(&(vcpu_regs->usr_reg[0]), regs->usr_regs8_12, sizeof(u32) * 5);
	memcpy(&(vcpu_regs->fiq_reg[0]), regs->fiq_regs8_12, sizeof(u32) * 5);
	vcpu_regs->banked_fiq[0] = regs->reg13[MODE_FIQ];
	vcpu_regs->banked_fiq[1] = regs->reg14[MODE_FIQ];
	vcpu_regs->banked_irq[0] = regs->reg13[MODE_IRQ];
	vcpu_regs->banked_irq[1] = regs->reg14[MODE_IRQ];
	vcpu_regs->banked_svc[0] = regs->reg13[MODE_SVC];
	vcpu_regs->banked_svc[1] = regs->reg14[MODE_SVC];
	vcpu_regs->banked_abt[0] = regs->reg13[MODE_ABORT];
	vcpu_regs->banked_abt[1] = regs->reg14[MODE_ABORT];
	vcpu_regs->banked_und[0] = regs->reg13[MODE_UNDEF];
	vcpu_regs->banked_und[1] = regs->reg14[MODE_UNDEF];
	vcpu_regs->banked_usr[0] = regs->reg13[MODE_USER];
	vcpu_regs->banked_usr[1] = regs->reg14[MODE_USER];

	vcpu_reg(vcpu, 15) = regs->reg15;
	kvm_cpsr_write(vcpu, regs->cpsr);
	memcpy(vcpu_regs->spsr, regs->spsr, sizeof(u32) * 5);

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
