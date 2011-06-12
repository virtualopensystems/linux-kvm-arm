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

#define USR_REG_OFFSET_0_7 \
	/* r0 */	offsetof(struct kvm_vcpu_arch, regs.usr_regs[0]), \
	/* r1 */	offsetof(struct kvm_vcpu_arch, regs.usr_regs[1]), \
	/* r2 */	offsetof(struct kvm_vcpu_arch, regs.usr_regs[2]), \
	/* r3 */	offsetof(struct kvm_vcpu_arch, regs.usr_regs[3]), \
	/* r4 */	offsetof(struct kvm_vcpu_arch, regs.usr_regs[4]), \
	/* r5 */	offsetof(struct kvm_vcpu_arch, regs.usr_regs[5]), \
	/* r6 */	offsetof(struct kvm_vcpu_arch, regs.usr_regs[6]), \
	/* r7 */	offsetof(struct kvm_vcpu_arch, regs.usr_regs[7])
#define USR_REG_OFFSET_8_12 \
	/* r8 */	offsetof(struct kvm_vcpu_arch, regs.usr_regs[8]), \
	/* r9 */	offsetof(struct kvm_vcpu_arch, regs.usr_regs[9]), \
	/* r10 */	offsetof(struct kvm_vcpu_arch, regs.usr_regs[10]), \
	/* r11 */	offsetof(struct kvm_vcpu_arch, regs.usr_regs[11]), \
	/* r12 */	offsetof(struct kvm_vcpu_arch, regs.usr_regs[12]) \

static unsigned long vcpu_reg_offsets[MODE_SYS + 1][16] =
{
	/* FIQ Registers */
	{
			USR_REG_OFFSET_0_7,
	/* r8 */	offsetof(struct kvm_vcpu_arch, regs.fiq_regs[0]),
	/* r9 */	offsetof(struct kvm_vcpu_arch, regs.fiq_regs[1]),
	/* r10 */	offsetof(struct kvm_vcpu_arch, regs.fiq_regs[2]),
	/* r11 */	offsetof(struct kvm_vcpu_arch, regs.fiq_regs[3]),
	/* r12 */	offsetof(struct kvm_vcpu_arch, regs.fiq_regs[4]),
	/* r13 */	offsetof(struct kvm_vcpu_arch, regs.fiq_regs[5]),
	/* r14 */	offsetof(struct kvm_vcpu_arch, regs.fiq_regs[6]),
	/* r15 */	offsetof(struct kvm_vcpu_arch, regs.pc),
	},

	/* IRQ Registers */
	{
			USR_REG_OFFSET_0_7,
			USR_REG_OFFSET_8_12,
	/* r13 */	offsetof(struct kvm_vcpu_arch, regs.irq_regs[0]),
	/* r14 */	offsetof(struct kvm_vcpu_arch, regs.irq_regs[1]),
	/* r15 */	offsetof(struct kvm_vcpu_arch, regs.pc),
	},

	/* SVC Registers */
	{
			USR_REG_OFFSET_0_7,
			USR_REG_OFFSET_8_12,
	/* r13 */	offsetof(struct kvm_vcpu_arch, regs.svc_regs[0]),
	/* r14 */	offsetof(struct kvm_vcpu_arch, regs.svc_regs[1]),
	/* r15 */	offsetof(struct kvm_vcpu_arch, regs.pc),
	},

	/* ABT Registers */
	{
			USR_REG_OFFSET_0_7,
			USR_REG_OFFSET_8_12,
	/* r13 */	offsetof(struct kvm_vcpu_arch, regs.abt_regs[0]),
	/* r14 */	offsetof(struct kvm_vcpu_arch, regs.abt_regs[1]),
	/* r15 */	offsetof(struct kvm_vcpu_arch, regs.pc),
	},

	/* UND Registers */
	{
			USR_REG_OFFSET_0_7,
			USR_REG_OFFSET_8_12,
	/* r13 */	offsetof(struct kvm_vcpu_arch, regs.und_regs[0]),
	/* r14 */	offsetof(struct kvm_vcpu_arch, regs.und_regs[1]),
	/* r15 */	offsetof(struct kvm_vcpu_arch, regs.pc),
	},

	/* USR Registers */
	{
			USR_REG_OFFSET_0_7,
			USR_REG_OFFSET_8_12,
	/* r13 */	offsetof(struct kvm_vcpu_arch, regs.usr_regs[13]),
	/* r14 */	offsetof(struct kvm_vcpu_arch, regs.usr_regs[14]),
	/* r15 */	offsetof(struct kvm_vcpu_arch, regs.pc),
	},

	/* SYS Registers */
	{
			USR_REG_OFFSET_0_7,
			USR_REG_OFFSET_8_12,
	/* r13 */	offsetof(struct kvm_vcpu_arch, regs.usr_regs[13]),
	/* r14 */	offsetof(struct kvm_vcpu_arch, regs.usr_regs[14]),
	/* r15 */	offsetof(struct kvm_vcpu_arch, regs.pc),
	},
};

/*
 * Return a pointer to the register number valid in the specified mode of
 * the virtual CPU.
 */
u32* kvm_vcpu_reg(struct kvm_vcpu *vcpu, u8 reg_num, u32 mode)
{
	BUG_ON(reg_num > 15);
	BUG_ON(mode > MODE_SYS);

	return (u32 *)((void *)&vcpu->arch + vcpu_reg_offsets[mode][reg_num]);
}
