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

#ifndef __ARM_KVM_TRANSLATE_H__
#define __ARM_KVM_TRANSLATE_H__


void kvmarm_translate_init(struct kvm_vcpu *vcpu);
int kvmarm_translate(struct kvm_vcpu *vcpu, gva_t instr);
u32 get_orig_instr(struct kvm_vcpu *vcpu, gva_t addr);
int get_trans_instr_index(u32 instr);
int get_branch_instr_index(u32 instr);




/*
 * Convert a translatable instruction into an internal identifier
 * for the instruction. If the instruction isn't one that needs
 * to be translated, TRANS_INSTR_NONE is returned.
 *
 * Input:  u32 *instr - The address to the instruction to translate
 *
 * Return: One of TRANS_INSTR_*
 */
int kvmarm_translate_getOp(u32 *instr);

/*
 * Determine if the translatable instruction returned by
 * kvmarm_translate_getOp is translated due to it being an
 * instruction that changes the control flow of the
 * program.
 */
int kvmarm_translate_isBranchOp(int op);


int get_instr_index(u32 instr, u32 table[][2], int table_entries);




#endif /* __ARM_KVM_TRANSLATE_H__ */
