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

#define USR_REG_OFFSET(_reg) \
	offsetof(struct kvm_vcpu_arch, regs.usr_regs[_reg])

static const unsigned long vcpu_reg_offsets[MODE_SYS + 1][16] = {
	/* FIQ Registers */
	{
		USR_REG_OFFSET(0), USR_REG_OFFSET(1), USR_REG_OFFSET(2),
		USR_REG_OFFSET(3), USR_REG_OFFSET(4), USR_REG_OFFSET(5),
		USR_REG_OFFSET(6), USR_REG_OFFSET(7),
		offsetof(struct kvm_vcpu_arch, regs.fiq_regs[1]), /* r8 */
		offsetof(struct kvm_vcpu_arch, regs.fiq_regs[1]), /* r9 */
		offsetof(struct kvm_vcpu_arch, regs.fiq_regs[2]), /* r10 */
		offsetof(struct kvm_vcpu_arch, regs.fiq_regs[3]), /* r11 */
		offsetof(struct kvm_vcpu_arch, regs.fiq_regs[4]), /* r12 */
		offsetof(struct kvm_vcpu_arch, regs.fiq_regs[5]), /* r13 */
		offsetof(struct kvm_vcpu_arch, regs.fiq_regs[6]), /* r14 */
		offsetof(struct kvm_vcpu_arch, regs.pc)		  /* r15 */
	},

	/* IRQ Registers */
	{
		USR_REG_OFFSET(0), USR_REG_OFFSET(1), USR_REG_OFFSET(2),
		USR_REG_OFFSET(3), USR_REG_OFFSET(4), USR_REG_OFFSET(5),
		USR_REG_OFFSET(6), USR_REG_OFFSET(7), USR_REG_OFFSET(8),
		USR_REG_OFFSET(9), USR_REG_OFFSET(10), USR_REG_OFFSET(11),
		USR_REG_OFFSET(12),
		offsetof(struct kvm_vcpu_arch, regs.irq_regs[0]), /* r13 */
		offsetof(struct kvm_vcpu_arch, regs.irq_regs[1]), /* r14 */
		offsetof(struct kvm_vcpu_arch, regs.pc)	          /* r15 */
	},

	/* SVC Registers */
	{
		USR_REG_OFFSET(0), USR_REG_OFFSET(1), USR_REG_OFFSET(2),
		USR_REG_OFFSET(3), USR_REG_OFFSET(4), USR_REG_OFFSET(5),
		USR_REG_OFFSET(6), USR_REG_OFFSET(7), USR_REG_OFFSET(8),
		USR_REG_OFFSET(9), USR_REG_OFFSET(10), USR_REG_OFFSET(11),
		USR_REG_OFFSET(12),
		offsetof(struct kvm_vcpu_arch, regs.svc_regs[0]), /* r13 */
		offsetof(struct kvm_vcpu_arch, regs.svc_regs[1]), /* r14 */
		offsetof(struct kvm_vcpu_arch, regs.pc)		  /* r15 */
	},

	/* ABT Registers */
	{
		USR_REG_OFFSET(0), USR_REG_OFFSET(1), USR_REG_OFFSET(2),
		USR_REG_OFFSET(3), USR_REG_OFFSET(4), USR_REG_OFFSET(5),
		USR_REG_OFFSET(6), USR_REG_OFFSET(7), USR_REG_OFFSET(8),
		USR_REG_OFFSET(9), USR_REG_OFFSET(10), USR_REG_OFFSET(11),
		USR_REG_OFFSET(12),
		offsetof(struct kvm_vcpu_arch, regs.abt_regs[0]), /* r13 */
		offsetof(struct kvm_vcpu_arch, regs.abt_regs[1]), /* r14 */
		offsetof(struct kvm_vcpu_arch, regs.pc)	          /* r15 */
	},

	/* UND Registers */
	{
		USR_REG_OFFSET(0), USR_REG_OFFSET(1), USR_REG_OFFSET(2),
		USR_REG_OFFSET(3), USR_REG_OFFSET(4), USR_REG_OFFSET(5),
		USR_REG_OFFSET(6), USR_REG_OFFSET(7), USR_REG_OFFSET(8),
		USR_REG_OFFSET(9), USR_REG_OFFSET(10), USR_REG_OFFSET(11),
		USR_REG_OFFSET(12),
		offsetof(struct kvm_vcpu_arch, regs.und_regs[0]), /* r13 */
		offsetof(struct kvm_vcpu_arch, regs.und_regs[1]), /* r14 */
		offsetof(struct kvm_vcpu_arch, regs.pc)	          /* r15 */
	},

	/* USR Registers */
	{
		USR_REG_OFFSET(0), USR_REG_OFFSET(1), USR_REG_OFFSET(2),
		USR_REG_OFFSET(3), USR_REG_OFFSET(4), USR_REG_OFFSET(5),
		USR_REG_OFFSET(6), USR_REG_OFFSET(7), USR_REG_OFFSET(8),
		USR_REG_OFFSET(9), USR_REG_OFFSET(10), USR_REG_OFFSET(11),
		USR_REG_OFFSET(12),
		offsetof(struct kvm_vcpu_arch, regs.usr_regs[13]), /* r13 */
		offsetof(struct kvm_vcpu_arch, regs.usr_regs[14]), /* r14 */
		offsetof(struct kvm_vcpu_arch, regs.pc)	           /* r15 */
	},

	/* SYS Registers */
	{
		USR_REG_OFFSET(0), USR_REG_OFFSET(1), USR_REG_OFFSET(2),
		USR_REG_OFFSET(3), USR_REG_OFFSET(4), USR_REG_OFFSET(5),
		USR_REG_OFFSET(6), USR_REG_OFFSET(7), USR_REG_OFFSET(8),
		USR_REG_OFFSET(9), USR_REG_OFFSET(10), USR_REG_OFFSET(11),
		USR_REG_OFFSET(12),
		offsetof(struct kvm_vcpu_arch, regs.usr_regs[13]), /* r13 */
		offsetof(struct kvm_vcpu_arch, regs.usr_regs[14]), /* r14 */
		offsetof(struct kvm_vcpu_arch, regs.pc)	           /* r15 */
	},
};

/*
 * Return a pointer to the register number valid in the specified mode of
 * the virtual CPU.
 */
u32 *kvm_vcpu_reg(struct kvm_vcpu *vcpu, u8 reg_num, u32 mode)
{
	BUG_ON(reg_num > 15);
	BUG_ON(mode > MODE_SYS);

	return (u32 *)((void *)&vcpu->arch + vcpu_reg_offsets[mode][reg_num]);
}
