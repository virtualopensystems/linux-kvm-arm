
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

#ifndef __ARM_KVM_EMULATE_H__
#define __ARM_KVM_EMULATE_H__

int  kvm_instr_index(u32 instr, u32 table[][2], int table_entries);
void kvm_emulate_init(struct kvm_vcpu_arch *vcpu);
void kvm_emulate_exception(struct kvm_vcpu_arch *vcpu);
int  kvm_handle_undefined(struct kvm_vcpu *vcpu, u32 instr);
int  kvm_emulate_sensitive(struct kvm_vcpu *vcpu, u32 instr);


int kvm_ls_is_write(struct kvm_vcpu *vcpu, u32 instr);
int kvm_ls_length(struct kvm_vcpu *vcpu, u32 instr);
int kvm_ls_get_address(struct kvm_vcpu *vcpu, u32 instr);
int kvm_ls_get_rd(struct kvm_vcpu *vcpu, u32 instr);
int kvm_ls_emulate_writeback(struct kvm_vcpu *vcpu, u32 instr);


/*
 * Bit fields and convenience functions for emulation
 */
#define BIT_SET(_val, _bitnum) \
	((_val & (1UL << (_bitnum))) >> (_bitnum))

#define BIT_CLEAR(__val, __bitnum) \
	(!BIT_SET(__val, __bitnum))

#define CHECK_BITS(_val, _mask, _pattern) \
	((_val & _mask) == _pattern)


/*
 * ARM instruction table indices. The actual tables recide in kvm_emulate.c
 */
#define INSTR_NONE	-1

#define INSTR_DP_ADC	 0
#define INSTR_DP_ADD	 1
#define INSTR_DP_AND	 2
#define INSTR_DP_BIC	 3
#define INSTR_DP_EOR	 4
#define INSTR_DP_MOV	 5
#define INSTR_DP_MVN	 6
#define INSTR_DP_ORR	 7
#define INSTR_DP_RSB	 8
#define INSTR_DP_RSC	 9
#define INSTR_DP_SBC	10
#define INSTR_DP_SUB	11

#define INSTR_PSR_CPS	 	0
#define INSTR_PSR_SETEND	1
#define INSTR_PSR_MRS		2
#define INSTR_PSR_MSR_IMM	3
#define INSTR_PSR_MSR_REG	4

#define INSTR_LS_LDRBT	 0
#define INSTR_LS_LDRT	 1
#define INSTR_LS_LDR	 2
#define INSTR_LS_LDRB	 3
#define INSTR_LS_LDRD	 4
#define INSTR_LS_LDREX	 5
#define INSTR_LS_LDRH	 6
#define INSTR_LS_LDRSB	 7
#define INSTR_LS_LDRSH	 8
#define INSTR_LS_STRBT	 9
#define INSTR_LS_STRT	10
#define INSTR_LS_STR	11
#define INSTR_LS_STRB	12
#define INSTR_LS_STRD	13
#define INSTR_LS_STREX	14
#define INSTR_LS_STRH	15

#define INSTR_LSMULT_LDM_1	 0
#define INSTR_LSMULT_LDM_2	 1
#define INSTR_LSMULT_LDM_3	 2
#define INSTR_LSMULT_STM_1	 3
#define INSTR_LSMULT_STM_2	 4

#define INSTR_COPROC_MCRR2	 0
#define INSTR_COPROC_MRRC2	 1
#define INSTR_COPROC_MCR2	 2
#define INSTR_COPROC_MRC2	 3
#define INSTR_COPROC_CDP	 4
#define INSTR_COPROC_LDC	 5
#define INSTR_COPROC_MCR	 6
#define INSTR_COPROC_MCRR	 7
#define INSTR_COPROC_MRC	 8
#define INSTR_COPROC_MRRC	 9
#define INSTR_COPROC_STC	 10

/*
 * Co-Processor 15 register 1 defines
 */
#define COPROC_REG1_IDCODES	0  /* Processor ID Codes */
#define COPROC_REG1_SYSCONF	1  /* System Configuration */
#define COPROC_REG1_PGTABLE	2  /* Page table */
#define COPROC_REG1_DAC		3  /* Domain Access Control */
#define COPROC_REG1_FSR		5  /* Instruction Fault Status Register */
#define COPROC_REG1_FAR		6  /* Fault Address Register */
#define COPROC_REG1_CACHE	7  /* Cache management functions */
#define COPROC_REG1_MMU_TLB	8  /* MMU TLB Control */
#define COPROC_REG1_CACHE_LCK	9  /* Cache lockdown functions */
#define COPROC_REG1_TLB_LCK	10 /* TLB Lockdown functions */
#define COPROC_REG1_PROC_ID	13 /* Process ID Register */


/*
 * Load-Store instruction decoding
 */
#define INSTR_LS_TYPE_BIT		26
#define INSTR_LS_RD_MASK		0x0000f000
#define INSTR_LS_RD_SHIFT		12
#define INSTR_LS_RN_MASK		0x000f0000
#define INSTR_LS_RN_SHIFT		16
#define INSTR_LS_RM_MASK		0x0000000f
#define INSTR_LS_OFFSET12_MASK		0x00000fff

#define INSTR_LS_BIT_P			24
#define INSTR_LS_BIT_U			23
#define INSTR_LS_BIT_B			22
#define INSTR_LS_BIT_W			21
#define INSTR_LS_BIT_L			20
#define INSTR_LS_BIT_S			 6
#define INSTR_LS_BIT_H			 5


/*
 * Load-Store multiple instruction decoding
 */
#define INSTR_LSM_REG_MASK		0xffff
#define INSTR_LSM_RN_SHIFT		16
#define INSTR_LSM_RN_MASK		(0xf << INSTR_LSM_RN_SHIFT)
#define INSTR_LSM_BIT_P			24
#define INSTR_LSM_BIT_U			23
#define INSTR_LSM_BIT_S			22
#define INSTR_LSM_BIT_W			21
#define INSTR_LSM_BIT_L			20


/*
 * ARM addressing mode defines
 */
#define OFFSET_IMM_MASK			0x0e000000
#define OFFSET_IMM_VALUE		0x04000000
#define OFFSET_REG_MASK			0x0e000ff0
#define OFFSET_REG_VALUE		0x06000000
#define OFFSET_SCALE_MASK		0x0e000010
#define OFFSET_SCALE_VALUE		0x06000000

#define SCALE_SHIFT_MASK		0x000000a0
#define SCALE_SHIFT_SHIFT		5
#define SCALE_SHIFT_LSL			0x0
#define SCALE_SHIFT_LSR			0x1
#define SCALE_SHIFT_ASR			0x2
#define SCALE_SHIFT_ROR_RRX		0x3
#define SCALE_SHIFT_IMM_MASK		0x00000f80
#define SCALE_SHIFT_IMM_SHIFT		6


#define PSR_BIT_C			29




#endif /* __ARM_KVM_EMULATE_H__ */
