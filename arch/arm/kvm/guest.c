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
#include <asm/kvm_asm.h>
#include <asm/kvm_emulate.h>

struct kvm_stats_debugfs_item debugfs_entries[] = {
	{ NULL }
};

int kvm_arch_vcpu_setup(struct kvm_vcpu *vcpu)
{
	return 0;
}

int kvm_arch_vcpu_ioctl_get_regs(struct kvm_vcpu *vcpu, struct kvm_regs *regs)
{
	struct kvm_vcpu_regs *vcpu_regs = &vcpu->arch.regs;

	/*
	 * GPRs and PSRs
	 */
	memcpy(regs->regs0_7, &(vcpu_regs->usr_regs[0]), sizeof(u32) * 8);
	memcpy(regs->usr_regs8_12, &(vcpu_regs->usr_regs[8]), sizeof(u32) * 5);
	memcpy(regs->fiq_regs8_12, &(vcpu_regs->fiq_regs[0]), sizeof(u32) * 5);
	regs->reg13[MODE_FIQ] = vcpu_regs->fiq_regs[5];
	regs->reg14[MODE_FIQ] = vcpu_regs->fiq_regs[6];
	regs->reg13[MODE_IRQ] = vcpu_regs->irq_regs[0];
	regs->reg14[MODE_IRQ] = vcpu_regs->irq_regs[1];
	regs->reg13[MODE_SVC] = vcpu_regs->svc_regs[0];
	regs->reg14[MODE_SVC] = vcpu_regs->svc_regs[1];
	regs->reg13[MODE_ABT] = vcpu_regs->abt_regs[0];
	regs->reg14[MODE_ABT] = vcpu_regs->abt_regs[1];
	regs->reg13[MODE_UND] = vcpu_regs->und_regs[0];
	regs->reg14[MODE_UND] = vcpu_regs->und_regs[1];
	regs->reg13[MODE_USR] = vcpu_regs->usr_regs[0];
	regs->reg14[MODE_USR] = vcpu_regs->usr_regs[1];

	regs->spsr[MODE_FIQ]  = vcpu_regs->fiq_regs[7];
	regs->spsr[MODE_IRQ]  = vcpu_regs->irq_regs[2];
	regs->spsr[MODE_SVC]  = vcpu_regs->svc_regs[2];
	regs->spsr[MODE_ABT]  = vcpu_regs->abt_regs[2];
	regs->spsr[MODE_UND]  = vcpu_regs->und_regs[2];

	regs->reg15 = vcpu_regs->pc;
	regs->cpsr = vcpu_regs->cpsr;


	/*
	 * Co-processor registers.
	 */
	regs->cp15.c0_midr = vcpu->arch.cp15[c0_MIDR];
	regs->cp15.c1_sys = vcpu->arch.cp15[c1_SCTLR];
	regs->cp15.c2_base0 = vcpu->arch.cp15[c2_TTBR0];
	regs->cp15.c2_base1 = vcpu->arch.cp15[c2_TTBR1];
	regs->cp15.c2_control = vcpu->arch.cp15[c2_TTBCR];
	regs->cp15.c3_dacr = vcpu->arch.cp15[c3_DACR];

	return 0;
}

int kvm_arch_vcpu_ioctl_set_regs(struct kvm_vcpu *vcpu, struct kvm_regs *regs)
{
	struct kvm_vcpu_regs *vcpu_regs = &vcpu->arch.regs;

	memcpy(&(vcpu_regs->usr_regs[0]), regs->regs0_7, sizeof(u32) * 8);
	memcpy(&(vcpu_regs->usr_regs[8]), regs->usr_regs8_12, sizeof(u32) * 5);
	memcpy(&(vcpu_regs->fiq_regs[0]), regs->fiq_regs8_12, sizeof(u32) * 5);

	vcpu_regs->fiq_regs[5] = regs->reg13[MODE_FIQ];
	vcpu_regs->fiq_regs[6] = regs->reg14[MODE_FIQ];
	vcpu_regs->irq_regs[0] = regs->reg13[MODE_IRQ];
	vcpu_regs->irq_regs[1] = regs->reg14[MODE_IRQ];
	vcpu_regs->svc_regs[0] = regs->reg13[MODE_SVC];
	vcpu_regs->svc_regs[1] = regs->reg14[MODE_SVC];
	vcpu_regs->abt_regs[0] = regs->reg13[MODE_ABT];
	vcpu_regs->abt_regs[1] = regs->reg14[MODE_ABT];
	vcpu_regs->und_regs[0] = regs->reg13[MODE_UND];
	vcpu_regs->und_regs[1] = regs->reg14[MODE_UND];
	vcpu_regs->usr_regs[0] = regs->reg13[MODE_USR];
	vcpu_regs->usr_regs[1] = regs->reg14[MODE_USR];

	vcpu_regs->fiq_regs[7] = regs->spsr[MODE_FIQ];
	vcpu_regs->irq_regs[2] = regs->spsr[MODE_IRQ];
	vcpu_regs->svc_regs[2] = regs->spsr[MODE_SVC];
	vcpu_regs->abt_regs[2] = regs->spsr[MODE_ABT];
	vcpu_regs->und_regs[2] = regs->spsr[MODE_UND];

	/*
	 * Co-processor registers.
	 */
	vcpu->arch.cp15[c0_MIDR] = regs->cp15.c0_midr;
	vcpu->arch.cp15[c1_SCTLR] = regs->cp15.c1_sys;

	vcpu_regs->pc = regs->reg15;
	vcpu_regs->cpsr = regs->cpsr;

	return 0;
}

int kvm_arch_vcpu_ioctl_get_sregs(struct kvm_vcpu *vcpu,
				  struct kvm_sregs *sregs)
{
	return -EINVAL;
}

int kvm_arch_vcpu_ioctl_set_sregs(struct kvm_vcpu *vcpu,
				  struct kvm_sregs *sregs)
{
	return -EINVAL;
}

int kvm_arch_vcpu_ioctl_get_fpu(struct kvm_vcpu *vcpu, struct kvm_fpu *fpu)
{
	return -EINVAL;
}

int kvm_arch_vcpu_ioctl_set_fpu(struct kvm_vcpu *vcpu, struct kvm_fpu *fpu)
{
	return -EINVAL;
}

int kvm_arch_vcpu_ioctl_translate(struct kvm_vcpu *vcpu,
				  struct kvm_translation *tr)
{
	return -EINVAL;
}
