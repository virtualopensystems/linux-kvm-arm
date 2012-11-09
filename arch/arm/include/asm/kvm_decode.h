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

#ifndef __ARM_KVM_DECODE_H__
#define __ARM_KVM_DECODE_H__

#include <linux/types.h>

struct kvm_vcpu;
struct kvm_exit_mmio;

struct kvm_decode {
	struct pt_regs *regs;
	unsigned long fault_addr;
	unsigned long rt;
	bool sign_extend;
};

int kvm_decode_load_store(struct kvm_decode *decode, unsigned long instr,
			  struct kvm_exit_mmio *mmio);

static inline unsigned long *kvm_decode_reg(struct kvm_decode *decode, int reg)
{
	return &decode->regs->uregs[reg];
}

static inline unsigned long *kvm_decode_cpsr(struct kvm_decode *decode)
{
	return &decode->regs->ARM_cpsr;
}

#endif /* __ARM_KVM_DECODE_H__ */
