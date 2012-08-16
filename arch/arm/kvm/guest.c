/*
 * Copyright (C) 2012 - Virtual Open Systems and Columbia University
 * Author: Christoffer Dall <c.dall@virtualopensystems.com>
 *
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

#define VM_STAT(x) { #x, offsetof(struct kvm, stat.x), KVM_STAT_VM }
#define VCPU_STAT(x) { #x, offsetof(struct kvm_vcpu, stat.x), KVM_STAT_VCPU }

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

	return 0;
}

int kvm_arch_vcpu_ioctl_set_regs(struct kvm_vcpu *vcpu, struct kvm_regs *regs)
{
	struct kvm_vcpu_regs *vcpu_regs = &vcpu->arch.regs;

	if (__vcpu_mode(regs->cpsr) == 0xf)
		return -EINVAL;

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

int kvm_vcpu_set_target(struct kvm_vcpu *vcpu,
			const struct kvm_vcpu_init *init)
{
	unsigned int i;

	/* We can only do a cortex A15 for now. */
	if (init->target != kvm_target_cpu())
		return -EINVAL;

	vcpu->arch.target = init->target;
	bitmap_zero(vcpu->arch.features, NUM_FEATURES);

	/* -ENOENT for unknown features, -EINVAL for invalid combinations. */
	for (i = 0; i < sizeof(init->features)*8; i++) {
		if (init->features[i / 32] & (1 << (i % 32))) {
			if (i >= NUM_FEATURES)
				return -ENOENT;
			set_bit(i, vcpu->arch.features);
		}
	}

	/* Now we know what it is, we can reset it. */
	return kvm_reset_vcpu(vcpu);
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
