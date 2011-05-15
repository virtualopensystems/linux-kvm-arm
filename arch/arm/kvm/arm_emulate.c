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

#include <asm/kvm_emulate.h>

/*
 * Return a pointer to the register number valid in the specified mode of
 * the virtual CPU.
 */
u32* kvm_vcpu_reg(struct kvm_vcpu *vcpu, u8 reg_num, u32 mode)
{
	struct kvm_vcpu_regs *regs;
	u8 reg_idx;
	BUG_ON(reg_num > 15);

	regs = &vcpu->arch.regs;

	/* The PC is trivial */
	if (reg_num == 15)
		return &(regs->pc);

	/* Non-banked registers */
	if (reg_num < 8)
		return &(regs->usr_regs[reg_num]);

	/* Banked registers r13 and r14 */
	if (reg_num >= 13) {
		reg_idx = reg_num - 13; /* 0=r13 and 1=r14 */
		switch (mode) {
		case MODE_FIQ:
			return &(regs->fiq_regs[reg_idx + 5]);
		case MODE_IRQ:
			return &(regs->irq_regs[reg_idx]);
		case MODE_SVC:
			return &(regs->svc_regs[reg_idx]);
		case MODE_ABT:
			return &(regs->abt_regs[reg_idx]);
		case MODE_UND:
			return &(regs->und_regs[reg_idx]);
		case MODE_USR:
		case MODE_SYS:
			return &(regs->usr_regs[reg_idx]);
		}
	}

	/* Banked FIQ registers r8-r12 */
	if (reg_num >= 8 && reg_num <= 12) {
		if (mode == MODE_FIQ) {
			reg_idx = reg_num - 8; /* 0=r8, ..., 4=r12 */
			return &(regs->fiq_regs[reg_idx]);
		} else
			return &(regs->usr_regs[reg_num]);
	}

	BUG();
	return NULL;
}
