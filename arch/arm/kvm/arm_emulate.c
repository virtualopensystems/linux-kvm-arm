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

#include <linux/bitops.h>
#include <linux/kvm_host.h>
#include <asm/kvm_arm.h>
#include <asm/system.h>
#include <asm/ptrace.h>
#include <asm/uaccess.h>
#include <asm/kvm_mmu.h>
#include <asm/kvm_emulate.h>

extern u8 guest_debug;

/*
 * Function prototypes
 */
static inline int get_coproc_op(u32 instr);
static int emulate_mcr(struct kvm_vcpu *vcpu, u32 instr);
static int emulate_mrc(struct kvm_vcpu *vcpu, u32 instr);
static int emulate_mcrr(struct kvm_vcpu *vcpu, u32 instr);
static int emulate_mrrc(struct kvm_vcpu *vcpu, u32 instr);

static inline int get_arm_ls_instr_index(u32 instr);
static inline int get_arm_lsmult_instr_index(u32 instr);
static int emulate_ls_mult(struct kvm_vcpu *vcpu, u32 instr);
static int emulate_ls_with_trans(struct kvm_vcpu *vcpu, u32 instr);

static inline int get_arm_privdp_instr_index(u32 instr);
//static int emulate_dp_instr(struct kvm_vcpu *vcpu, u32 instr, int op);
static int emulate_sensitive_dp_instr(struct kvm_vcpu *vcpu, u32 instr);

static inline int get_arm_psr_instr_index(u32 instr);
static int emulate_msr(struct kvm_vcpu *vcpu, u32 instr);
static int emulate_mrs(struct kvm_vcpu *vcpu, u32 instr);
static int emulate_cps(struct kvm_vcpu *vcpu, u32 instr);


/******************************************************************************
 * Utility functions common for all emulation code
 *****************************************************************************/

/*
 * This one accepts a matrix where the first element is the
 * bits as they must be, and the second element is the bitmask.
 */
int kvm_instr_index(u32 instr, u32 table[][2], int table_entries)
{
	int i;
	u32 mask;

	for (i = 0; i < table_entries; i++) {
		mask = table[i][1];
		if ((table[i][0] & mask) == (instr & mask))
			return i;
	}
	return INSTR_NONE;
}


/******************************************************************************
 * Entry points for emulation functions:
 *  - kvm_handle_undefined (Privilege instr. generate undefined exceptions)
 *  - kvm_emulate_sensitive (Sensitive instr., patched need to be emulated)
 *****************************************************************************/

/*
 * Handle an undefined exception.
 *
 * An undefined exception can happen by running a privileged instruction in
 * user mode or by actually executing an undefined instruction.
 */
#define COPROC_CPNUM_MASK 0x00000f00
int kvm_handle_undefined(struct kvm_vcpu *vcpu, u32 instr)
{      
	int ret;
	u32 cp_num = ((instr & COPROC_CPNUM_MASK) >> 8);
	int op = get_coproc_op(instr);	

	if (vcpu->arch.mode == MODE_USER)
		goto handle_in_guest;
	if (op == INSTR_NONE)
		goto handle_in_guest;
	if (cp_num != 15)
		goto handle_in_guest;

	switch (op) {
	case INSTR_COPROC_CDP:
	case INSTR_COPROC_LDC:
	case INSTR_COPROC_STC:
		/* Not supported for CP15 */
		goto handle_in_guest;
	case INSTR_COPROC_MCR:
		ret = emulate_mcr(vcpu, instr);
		break;
	case INSTR_COPROC_MCRR:
		ret = emulate_mcrr(vcpu, instr);
		break;
	case INSTR_COPROC_MRC:
		ret = emulate_mrc(vcpu, instr);
		break;
	case INSTR_COPROC_MRRC:
		ret = emulate_mrrc(vcpu, instr);
		break;
	default:
		ret = -EINVAL;
	}

	/* The instruction was emulated, proceed to next one */
	vcpu->arch.regs[15] += 4;
	if (ret)
		kvm_err(ret, "error when handling undefined exception");
	return ret;
handle_in_guest:
	printk(KERN_DEBUG "  handle undefined in guest: 0x%08x\n",
		vcpu->arch.regs[15]);
	KVMARM_NOT_IMPLEMENTED();
	vcpu->arch.exception_pending |= EXCEPTION_UNDEFINED;
	return 0;
}

int kvm_emulate_sensitive(struct kvm_vcpu *vcpu, u32 instr)
{
	int op, ret = 0;

	/* Is it a privileged data-processing instruction? */
	op = get_arm_privdp_instr_index(instr);
	if (op != INSTR_NONE) {
		ret = emulate_sensitive_dp_instr(vcpu, instr);
		return ret;
	}

	/* Is it a status-register instruction? */
	op = get_arm_psr_instr_index(instr);
	switch (op) {
	case INSTR_PSR_MRS: {
		ret = emulate_mrs(vcpu, instr);
		return ret;
	}
	case INSTR_PSR_MSR_IMM:
	case INSTR_PSR_MSR_REG: {
		ret = emulate_msr(vcpu, instr);
		return ret;
	}
	case INSTR_PSR_CPS: {
		ret = emulate_cps(vcpu, instr);
		return ret;
	}
	case INSTR_PSR_SETEND: {
		KVMARM_NOT_IMPLEMENTED();
	}
	default:
		break;
	}

	/* Is it a sensitive load/store multiple instruction? */
	op = get_arm_lsmult_instr_index(instr);
	switch (op) {
	case INSTR_LSMULT_LDM_2:
	case INSTR_LSMULT_LDM_3:
	case INSTR_LSMULT_STM_2:
		ret = emulate_ls_mult(vcpu, instr);
		return ret;
	default:
		break;
	}

	/* Is it a load/store with translation instruction? */
	op = get_arm_ls_instr_index(instr);
	switch (op) {
	case INSTR_LS_LDRT:
	case INSTR_LS_LDRBT:
	case INSTR_LS_STRT:
	case INSTR_LS_STRBT:
		/* The PC is set according to emulation result */
		return emulate_ls_with_trans(vcpu, instr);
	default:
		break;
	}

	printk(KERN_ERR "kvm_emulate_sensitive: unknown privileged "
			"instruction at 0x%08x: 0x%08x\n",
			(unsigned int)vcpu->arch.regs[15],
			(unsigned int)instr);
	return -EINVAL;
}


/******************************************************************************
 * CO-Processor emulation
 *****************************************************************************/

/*
 * Co-processor instruction definitions
 * (should maybe go in separate file or something
 */

#define NUM_COPROC_INSTR 7
static u32 coproc_instr[NUM_COPROC_INSTR][2] = {
                {0x0e000000, 0x0f000010} /* CDP     */
               ,{0x0c100000, 0x0e100000} /* LDC     */
               ,{0x0e000010, 0x0f100010} /* MCR     */
               ,{0x0c400000, 0x0ff00000} /* MCRR    */
               ,{0x0e100010, 0x0f100010} /* MRC     */
               ,{0x0c500000, 0x0ff00000} /* MRRC    */
               ,{0x0c000000, 0x0d000000} /* STC     */
};

/* Currently only handles MRC and MCR */
static inline int get_coproc_op(u32 instr)
{
	return kvm_instr_index(instr, coproc_instr, NUM_COPROC_INSTR);
}

struct coproc_params {
	struct kvm_vcpu *vcpu;
	u32 instr;
	int opcode1;
	int rd_reg;
	int CRn;
	int CRm;
	int opcode2;
	int is_write;
};

static int emulate_mrc_idcodes(struct coproc_params *params)
{
	struct kvm_vcpu *vcpu = params->vcpu;
	int rd_reg = params->rd_reg;
	int ret = 0;

	if (params->opcode1 != 0) {
		kvm_err(-EINVAL, "unsupported opcode1 (%d)", params->opcode1);
		return -EINVAL;
	}

	switch (params->CRm) {
	case 0:
		switch (params->opcode2) {
		case 0:
			VCPU_REG(vcpu, rd_reg) = vcpu->arch.cp15.c0_MIDR;
			break;
		case 1:
			VCPU_REG(vcpu, rd_reg) = vcpu->arch.cp15.c0_CTR;
			break;
		case 2:
			VCPU_REG(vcpu, rd_reg) = vcpu->arch.cp15.c0_TCMTR;
			break;
		case 3:
			VCPU_REG(vcpu, rd_reg) = vcpu->arch.cp15.c0_TLBTR;
			break;
		default:
			ret = -EINVAL;
		}
		break;
	case 1:
		KVMARM_NOT_IMPLEMENTED();
		break;
	case 2:
		KVMARM_NOT_IMPLEMENTED();
		break;
	default:
		ret = -EINVAL;
	}

	if (ret)
		kvm_err(ret, "invalid operation: CRm (%d), Op2 (%d)",
				params->CRm, params->opcode2);
	return ret;
}

static int emulate_mcr_sysconf(struct coproc_params *params)
{
	struct kvm_vcpu *vcpu = params->vcpu;
	int rd_reg = params->rd_reg;
	u32 rd_val = VCPU_REG(vcpu, rd_reg);

	if (params->CRm != 0 || params->opcode1 != 0) {
		kvm_err(-EINVAL, "unsupported CRm (%d) or opcode1 (%d)",
				params->CRm, params->opcode1);
		return -EINVAL;
	}

	switch (params->opcode2) {
	case 0: {
		/* Control Register */
		if ((rd_val & 0x1) != (vcpu->arch.cp15.c1_CR & 0x1)) {
			kvm_init_l1_shadow(vcpu, vcpu->arch.shadow_pgtable->pgd);
			if (rd_val & 0x1)
				kvm_msg("guest enabled MMU at: %08x",
						VCPU_REG(vcpu, 15));
			else
				kvm_msg("guest disabled MMU at: %08x",
						VCPU_REG(vcpu, 15));
		}

		vcpu->arch.cp15.c1_CR = rd_val;
		break;
	}
	case 1:
		/* Auxilliary Control Register */
		vcpu->arch.cp15.c1_ACR = VCPU_REG(vcpu, rd_reg);
		break;
	case 2:
		/* Control processor access register */
		vcpu->arch.cp15.c1_CAR = VCPU_REG(vcpu, rd_reg);
		break;
	default:
		kvm_err(-EINVAL, "unknown opcode2: %d", params->opcode2);
		return -EINVAL;
	}

	return 0;
}

static int emulate_mrc_sysconf(struct coproc_params *params)
{
	struct kvm_vcpu *vcpu = params->vcpu;
	int rd_reg = params->rd_reg;

	if (params->CRm != 0 || params->opcode1 != 0) {
		kvm_err(-EINVAL, "unsupported CRm (%d) or opcode1 (%d)",
				params->CRm, params->opcode1);
		return -EINVAL;
	}

	switch (params->opcode2) {
	case 0:
		/* Control Register */
		VCPU_REG(vcpu, rd_reg) = vcpu->arch.cp15.c1_CR;
		break;
	case 1:
		/* Auxilliary Control Register */
		VCPU_REG(vcpu, rd_reg) = vcpu->arch.cp15.c1_ACR;
		break;
	case 2:
		/* Control processor access register */
		VCPU_REG(vcpu, rd_reg) = vcpu->arch.cp15.c1_CAR;
		break;
	default:
		kvm_err(-EINVAL, "unknown opcode2: %d", params->opcode2);
		return -EINVAL;
	}

	return 0;
}

static int emulate_mcr_pgtable(struct coproc_params *params)
{
	struct kvm_vcpu *vcpu = params->vcpu;
	u32 rd_val = VCPU_REG(vcpu, params->rd_reg);

	if (params->CRm != 0 || params->opcode1 != 0) {
		kvm_err(-EINVAL, "unsupported CRm (%d) or opcode1 (%d)",
				params->CRm, params->opcode1);
		return -EINVAL;
	}

	switch (params->opcode2) {
	case 0: {
		gpa_t prev_base = vcpu->arch.cp15.c2_TTBR0;
		vcpu->arch.cp15.c2_TTBR0 = rd_val;
		kvm_msg("guest changed TTBR0 to: 0x%08x", rd_val);
		if (kvm_mmu_enabled(vcpu) && prev_base != rd_val) {
			return kvm_init_l1_shadow(vcpu,
						  vcpu->arch.shadow_pgtable->pgd);
		}
		break;
	}
	case 1: {
		gpa_t prev_base = vcpu->arch.cp15.c2_TTBR1;
		vcpu->arch.cp15.c2_TTBR1 = rd_val;
		kvm_msg("guest changed TTBR1 to: 0x%08x", rd_val);
		if (kvm_mmu_enabled(vcpu) && prev_base != rd_val) {
			return kvm_init_l1_shadow(vcpu,
						  vcpu->arch.shadow_pgtable->pgd);
		}
		break;
	}
	case 2:
		BUG_ON((rd_val & ~0x7) != 0);
		vcpu->arch.cp15.c2_TTBR_CR = rd_val;
		if ((rd_val & 0x7) != 0) {
			kvm_err(-EINVAL, "dont' support use of TTBR1 yet");
			return -EINVAL;
		}
		break;
	default:
		kvm_err(-EINVAL, "unknown opcode2: %d", params->opcode2);
		return -EINVAL;
	}

	return 0;
}

static int emulate_mrc_pgtable(struct coproc_params *params)
{
	struct kvm_vcpu *vcpu = params->vcpu;

	if (params->CRm != 0 || params->opcode1 != 0) {
		kvm_err(-EINVAL, "unsupported CRm (%d) or opcode1 (%d)",
				params->CRm, params->opcode1);
		return -EINVAL;
	}

	switch (params->opcode2) {
	case 0:
		VCPU_REG(vcpu, params->rd_reg) = vcpu->arch.cp15.c2_TTBR0;
		break;
	case 1:
		VCPU_REG(vcpu, params->rd_reg) = vcpu->arch.cp15.c2_TTBR1;
		break;
	case 2:
		/* TODO: (ARMv6) error, undefined exception */
		VCPU_REG(vcpu, params->rd_reg) = vcpu->arch.cp15.c2_TTBR_CR;
		break;
	default:
		kvm_err(-EINVAL, "unknown opcode2: %d", params->opcode2);
		return -EINVAL;
	}

	return 0;
}

static int emulate_mcr_dac(struct coproc_params *params)
{
	int i;
	struct kvm_vcpu *vcpu = params->vcpu;
	u32 old = vcpu->arch.cp15.c3_DACR;
	u32 new = VCPU_REG(vcpu, params->rd_reg);

	if (params->CRm != 0 || params->opcode1 != 0 || params->opcode2 != 0) {
		kvm_err(-EINVAL, "unsupported CRm (%d) or opcode1 (%d) "
				 "or opcode2 (%d)", params->CRm,
				 params->opcode1, params->opcode2);
		return -EINVAL;
	}

	vcpu->arch.cp15.c3_DACR = new;
	if (guest_debug) {
		kvm_msg("guest wrote DACR at 0x%08x from register %u: 0x%08x",
			VCPU_REG(vcpu, 15) - 4,
			params->rd_reg,
			vcpu->arch.cp15.c3_DACR);
	}

	/* Check if we need to update L2 ap's for special pages L1 domains */
	for (i = 0; i < 16; i++) {
		if (((old >> (i*2)) & 0x3) != ((new >> (i*2)) & 0x3)) {
			kvm_init_l1_shadow(vcpu, vcpu->arch.shadow_pgtable->pgd);
			/*
			kvm_update_special_region_ap(vcpu,
						     vcpu->arch.shadow_pgtable,
						     i);
						     */
		}
	}

	return 0;
}

static int emulate_mrc_dac(struct coproc_params *params)
{
	struct kvm_vcpu *vcpu = params->vcpu;

	if (params->CRm != 0 || params->opcode1 != 0 || params->opcode2 != 0) {
		kvm_err(-EINVAL, "unsupported CRm (%d) or opcode1 (%d) "
				 "or opcode2 (%d)", params->CRm,
				 params->opcode1, params->opcode2);
		return -EINVAL;
	}

	VCPU_REG(vcpu, params->rd_reg) = vcpu->arch.cp15.c3_DACR;
	if (guest_debug) {
		kvm_msg("guest read DACR: 0x%08x", vcpu->arch.cp15.c3_DACR);
	}
	return 0;
}

static int emulate_mcr_fsr(struct coproc_params *params)
{
	struct kvm_vcpu *vcpu = params->vcpu;

	if (params->CRm != 0 || params->opcode1 != 0) {
		kvm_err(-EINVAL, "unsupported CRm (%d) or opcode1 (%d)",
				params->CRm, params->opcode1);
		return -EINVAL;
	}

	switch (params->opcode2) {
	case 0:   
		vcpu->arch.cp15.c5_DFSR = VCPU_REG(vcpu, params->rd_reg);
		break;
	case 1:
		if (cpu_architecture() < CPU_ARCH_ARMv6) {
			kvm_msg("unsupported write IFSR on pre v6 archs");
			return -EINVAL;
		}
		vcpu->arch.cp15.c5_IFSR = VCPU_REG(vcpu, params->rd_reg);
		break;
	default:
		kvm_err(-EINVAL, "unknown opcode2: %d", params->opcode2);
		return -EINVAL;
	}

	return 0;
}

static int emulate_mrc_fsr(struct coproc_params *params)
{
	struct kvm_vcpu *vcpu = params->vcpu;

	if (params->CRm != 0 || params->opcode1 != 0) {
		kvm_err(-EINVAL, "unsupported CRm (%d) or opcode1 (%d)",
				params->CRm, params->opcode1);
		return -EINVAL;
	}

	switch (params->opcode2) {
	case 0:   
		VCPU_REG(vcpu, params->rd_reg) = vcpu->arch.cp15.c5_DFSR;
		break;
	case 1:
		/* TODO: (ARMv6) error, undefined exception */
	default:
		kvm_err(-EINVAL, "unknown opcode2: %d", params->opcode2);
		return -EINVAL;
	}

	return 0;
}

static int emulate_mcr_far(struct coproc_params *params)
{
	struct kvm_vcpu *vcpu = params->vcpu;

	if (params->CRm != 0 || params->opcode1 != 0) {
		kvm_err(-EINVAL, "unsupported CRm (%d) or opcode1 (%d)",
				params->CRm, params->opcode1);
		return -EINVAL;
	}

	switch (params->opcode2){
	case 0:
		vcpu->arch.cp15.c6_FAR = VCPU_REG(vcpu, params->rd_reg);
		break;
	case 1:
		/* TODO: (ARMv6) error, undefined exception */
		KVMARM_NOT_IMPLEMENTED();
	default:
		kvm_err(-EINVAL, "unknown opcode2: %d", params->opcode2);
		return -EINVAL;
	}

	return 0;
}

static int emulate_mrc_far(struct coproc_params *params)
{
	struct kvm_vcpu *vcpu = params->vcpu;

	if (params->CRm != 0 || params->opcode1 != 0) {
		kvm_err(-EINVAL, "unsupported CRm (%d) or opcode1 (%d)",
				params->CRm, params->opcode1);
		return -EINVAL;
	}

	switch (params->opcode2){
	case 0:
		VCPU_REG(vcpu, params->rd_reg) = vcpu->arch.cp15.c6_FAR;
		break;
	case 1:
		/* TODO: (ARMv6) error, undefined exception */
		KVMARM_NOT_IMPLEMENTED();
	default:
		kvm_err(-EINVAL, "unknown opcode2: %d", params->opcode2);
		return -EINVAL;
	}

	return 0;
}

extern void v6_flush_kern_cache_all(void);
static int emulate_mcr_cache(struct coproc_params *params)
{
	struct kvm_vcpu *vcpu = params->vcpu;
	int ret = 0;

	if (params->opcode1 != 0) {
		kvm_err(-EINVAL, "unsupported opcode1 (%d)", params->opcode1);
		return -EINVAL;
	}

	switch (params->CRm) {
	case 0:
		if (params->opcode2 == 4) {
			/* Wait for interrupt */
			vcpu->arch.wait_for_interrupts = 1;
			return 0;
		} else {
			ret = -EINVAL;
		}
		break;
	case 5:
		switch (params->opcode2) {
		case 0:	/* Invalidate entire i-cache */
			asm volatile("mcr	p15, 0, %[zero], c7, c5, 0":
					: [zero] "r" (0));
			break;
		case 1:	/* Invalidate i-cache line - MVA */
		case 2:	/* Invalidate i-cache line - set */
		case 4:	/* Flush prefetch buffer */
		case 6:	/* Flush entire branch target cache */
		case 7:	/* Flush branch target cache - MVA */
			//return kvm_init_l1_shadow(vcpu, vcpu->arch.shadow_pgtable);
			kvm_msg("not implemented operation: CRm (%d), Op2 (%d)",
					params->CRm, params->opcode2);
			KVMARM_NOT_IMPLEMENTED();
		default:
			ret = -EINVAL;
		}
		break;
	case 6:
		switch (params->opcode2) {
		case 0:	/* Invalidate entire data cache */
		case 1:	/* Invalidate data cache line - MVA */
		case 2:	/* Invalidate data cache line - set */
			//return kvm_init_l1_shadow(vcpu, vcpu->arch.shadow_pgtable);
			kvm_msg("not implemented operation: CRm (%d), Op2 (%d)",
					params->CRm, params->opcode2);
			KVMARM_NOT_IMPLEMENTED();
		default:
			ret = -EINVAL;
		}
		break;
	case 7:
		switch (params->opcode2) {
		case 0:	/* Invalidate both i-cache and d-cache */
			asm volatile("mcr	p15, 0, %[zero], c7, c5, 0":
					: [zero] "r" (0));
			asm volatile("mcr	p15, 0, %[zero], c7, c14, 0":
					: [zero] "r" (0));
			/*asm volatile("mcr	p15, 0, %[zero], c7, c7, 0":
					: [zero] "r" (0));*/
			break;
		case 1:	/* Invalidate unified cache line - MVA */
		case 2: /* Invalidate unified cache line - set */
			//return kvm_init_l1_shadow(vcpu, vcpu->arch.shadow_pgtable);
			kvm_msg("not implemented operation: CRm (%d), Op2 (%d)",
					params->CRm, params->opcode2);
			KVMARM_NOT_IMPLEMENTED();
		default:
			ret = -EINVAL;
		}
		break;
	case 10:
		switch (params->opcode2) {
		case 0:	/* Clean entire data cache */
			kvm_msg("not implemented operation: CRm (%d), Op2 (%d)",
					params->CRm, params->opcode2);
			KVMARM_NOT_IMPLEMENTED();
		case 1:	/* Clean data cache line - MVA */
			asm volatile("mcr	p15, 0, %[mva], c7, c10, 1":
					: [mva] "r" (VCPU_REG(vcpu, params->rd_reg)));
			break;
		case 2:	/* Clean data cache line - set */
		case 3:	/* test and clean */
		case 4:	/* Data synchronization barrier */
		case 5:	/* Data memory barrier */
			//return kvm_init_l1_shadow(vcpu, vcpu->arch.shadow_pgtable);
			kvm_msg("not implemented operation: CRm (%d), Op2 (%d)",
					params->CRm, params->opcode2);
			KVMARM_NOT_IMPLEMENTED();
		default:
			ret = -EINVAL;
		}
		break;
	case 11:
		switch (params->opcode2) {
		case 0:	/* Clean entire unified cache */
		case 1:	/* Clean unified cache line - MVA */
		case 2:	/* Clean unified cache line - set */
			//return kvm_init_l1_shadow(vcpu, vcpu->arch.shadow_pgtable);
			kvm_msg("not implemented operation: CRm (%d), Op2 (%d)",
					params->CRm, params->opcode2);
			KVMARM_NOT_IMPLEMENTED();
		}
		break;
	case 13:
		if (params->opcode2 == 1) {
			/* Prefetch i-cache line */
			kvm_msg("not implemented operation: CRm (%d), Op2 (%d)",
					params->CRm, params->opcode2);
			KVMARM_NOT_IMPLEMENTED();
		} else {
			ret = -EINVAL;
		}
		break;
	case 14:
		switch (params->opcode2) {
		case 0:	/* Clean and invalidate entire d-cache */
			asm volatile("mcr	p15, 0, %[zero], c7, c14, 0":
					: [zero] "r" (0));
			break;
		case 1:	/* Clean and invalidate d-cache line - MVA */
			asm volatile("mcr	p15, 0, %[mva], c7, c14, 2":
					: [mva] "r" (VCPU_REG(vcpu, params->rd_reg)));
			break;
		case 2:	/* Clean and invalidate d-cache line - set */
		case 3:	/* Test, clean, and invalidate */
			kvm_msg("not implemented operation: CRm (%d), Op2 (%d)",
					params->CRm, params->opcode2);
			KVMARM_NOT_IMPLEMENTED();
			//return kvm_init_l1_shadow(vcpu, vcpu->arch.shadow_pgtable);
			//v6_flush_kern_cache_all();
			break;
		default:
			ret = -EINVAL;
		}
		break;
	case 15:
		switch (params->opcode2) {
		case 0:	/* Clean and invalidate entire unified cache */
			asm volatile("mcr	p15, 0, %[zero], c7, c15, 0":
					: [zero] "r" (0));
			break;
		case 1:	/* Clean and invalidate unified cache line - MVA */
		case 2:	/* Clean and invalidate unified cache line - set */
			//return kvm_init_l1_shadow(vcpu, vcpu->arch.shadow_pgtable);
			kvm_msg("not implemented operation: CRm (%d), Op2 (%d)",
					params->CRm, params->opcode2);
			KVMARM_NOT_IMPLEMENTED();
		default:
			ret = -EINVAL;
		}
		break;
	default:
		ret = -EINVAL;
	}

	if (ret)
		kvm_err(ret, "invalid operation: CRm (%d), Op2 (%d)",
				params->CRm, params->opcode2);
	return ret;
}

static int emulate_mrc_cache(struct coproc_params *params)
{
	int ret = 0;

	switch (params->CRm) {
	case 10:
		if (params->opcode2 == 6) {
			KVMARM_NOT_IMPLEMENTED();
		} else {
			ret = -EINVAL;
		}
		break;
	case 12: /* Read Block Transfer Status Register */
		if (params->opcode2 == 4) {
			KVMARM_NOT_IMPLEMENTED();
		} else {
			ret = -EINVAL;
		}
		break;
	default:
		return -EINVAL;
	}

	if (ret)
		kvm_err(ret, "invalid operation: CRm (%d), Op2 (%d)",
				params->CRm, params->opcode2);
	return ret;
}

static int emulate_mcr_mmu_tlb(struct coproc_params *params)
{
	struct kvm_vcpu *vcpu = params->vcpu;
	int ret = 0;

	switch (params->CRm) {
	case 5:
		switch (params->opcode2) {
		case 0:	/* Invalidate entire instruction TLB */
		case 1:	/* Invalidate instruction single entry - MVA */
		case 2:	/* Invalidate on ASID match instruction TLB - ASID */
			ret = kvm_init_l1_shadow(vcpu,
						 vcpu->arch.shadow_pgtable->pgd);
			break;
		default:
			ret = -EINVAL;
		}
		break;
	case 6:
		switch (params->opcode2) {
		case 0: /* Invalidate entire data TLB */
		case 1: /* Invalidate instruction single entry */
		case 2: /* Invalidate on ASID match data TLB - ASID */
			return kvm_init_l1_shadow(vcpu,
						  vcpu->arch.shadow_pgtable->pgd);
		default:
			ret = -EINVAL;
		}
		break;
	case 7:
		switch (params->opcode2) {
		case 0:	/* Invalidate entire unified TLB */
		case 1:	/* Invalidate unified single entry - MVA */
		case 2:	/* Invalidate on AISD match unfied TLB - ASID */
			ret= kvm_init_l1_shadow(vcpu,
						vcpu->arch.shadow_pgtable->pgd);
			break;
		default:
			ret = -EINVAL;
		}
		break;
	default:
		ret = -EINVAL;
	}

	if (ret)
		kvm_err(ret, "invalid operation: CRm (%d), Op2 (%d)",
				params->CRm, params->opcode2);
	return ret;
}

static int emulate_mcr_cache_lck(struct coproc_params *params)
{
	struct kvm_vcpu *vcpu = params->vcpu;
	int rd = params->rd_reg;
	int ret = 0;

	if (params->opcode1 != 0) {
		kvm_err(-EINVAL, "unsupported opcode1 (%d)", params->opcode1);
		return -EINVAL;
	}

	switch (params->CRm) {
	case 0:
		if (params->opcode2 == 0)
			vcpu->arch.cp15.c9_DCLR = VCPU_REG(vcpu, rd);
		else if (params->opcode2 == 1)
			vcpu->arch.cp15.c9_ICLR = VCPU_REG(vcpu, rd);
		else
			ret = -EINVAL;
		break;
	case 1:
		if (params->opcode2 == 0) 
			vcpu->arch.cp15.c9_DTCMR = VCPU_REG(vcpu, rd);
		else if (params->opcode2 == 1)
			vcpu->arch.cp15.c9_ITCMR = VCPU_REG(vcpu, rd);
		else
			ret = -EINVAL;
		break;
	default:
		ret = -EINVAL;
	}

	if (ret)
		kvm_err(ret, "invalid operation: CRm (%d), Op2 (%d)",
				params->CRm, params->opcode2);
	return ret;
}

static int emulate_mrc_cache_lck(struct coproc_params *params)
{
	struct kvm_vcpu *vcpu = params->vcpu;
	int rd = params->rd_reg;
	int ret = 0;

	if (params->opcode1 != 0) {
		kvm_err(-EINVAL, "unsupported opcode1 (%d)", params->opcode1);
		return -EINVAL;
	}

	switch (params->CRm) {
	case 0:
		if (params->opcode2 == 0)
			VCPU_REG(vcpu, rd) = vcpu->arch.cp15.c9_DCLR;
		else if (params->opcode2 == 1)
			VCPU_REG(vcpu, rd) = vcpu->arch.cp15.c9_ICLR;
		else
			ret = -EINVAL;
		break;
	case 1:
		if (params->opcode2 == 0)
			VCPU_REG(vcpu, rd) = vcpu->arch.cp15.c9_DTCMR;
		else if (params->opcode2 == 1)
			VCPU_REG(vcpu, rd) = vcpu->arch.cp15.c9_ITCMR;
		else
			ret = -EINVAL;
		break;
	default:
		ret = -EINVAL;
	}

	if (ret)
		kvm_err(ret, "invalid operation: CRm (%d), Op2 (%d)",
				params->CRm, params->opcode2);
	return ret;
}

int emulate_mcr_tlb_lck(struct coproc_params *params)
{
	int ret = 0;

	/* XXX: This code is not valid for ARM1136 processors! */
	KVMARM_NOT_IMPLEMENTED();

	if (params->opcode1 != 0) {
		kvm_err(-EINVAL, "unsupported opcode1 (%d)", params->opcode1);
		return -EINVAL;
	}

	switch (params->CRm) {
	case 0:
		switch (params->opcode2){
		case 0:	/* Data lockdown register */
			break;
		case 1:	/* Instruction lockdown register */
			break;
		default:
			ret = -EINVAL;
		}
		break;
	case 4:
		switch (params->opcode2) {
		case 0:	/* Translate and lock I TLB entry */
			break;
		case 1:	/* Unlock I TLB */
			break;
		default:
			ret = -EINVAL;
		}
		break;
	case 8:
		switch (params->opcode2) {
		case 0:	/* Translate and lock D TLB entry */
			break;
		case 1:	/* Unlock D TLB */
			break;
		default:
			ret = -EINVAL;
		}
		break;
	default:
		ret = -EINVAL;
	}

	if (ret)
		kvm_err(ret, "invalid operation: CRm (%d), Op2 (%d)",
				params->CRm, params->opcode2);
	return ret;
}

static int emulate_mcr_proc_id(struct coproc_params *params)
{
	struct kvm_vcpu *vcpu = params->vcpu;

	if (params->CRm != 0 || params->opcode1 != 0) {
		kvm_err(-EINVAL, "unsupported CRm (%d) or opcode1 (%d)",
				params->CRm, params->opcode1);
		return -EINVAL;
	}

	switch (params->opcode2) {
	case 0:
		vcpu->arch.cp15.c13_FCSER = VCPU_REG(vcpu, params->rd_reg);
		break;
	case 1:
		vcpu->arch.cp15.c13_CID = VCPU_REG(vcpu, params->rd_reg);
		break;
	case 2:
		vcpu->arch.cp15.c13_TIDURW = VCPU_REG(vcpu, params->rd_reg);
		break;
	case 3:
		vcpu->arch.cp15.c13_TIDURO = VCPU_REG(vcpu, params->rd_reg);
		break;
	case 4:
		vcpu->arch.cp15.c13_TIDPO = VCPU_REG(vcpu, params->rd_reg);
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

static int emulate_mrc_proc_id(struct coproc_params *params)
{
	struct kvm_vcpu *vcpu = params->vcpu;

	if (params->CRm != 0 || params->opcode1 != 0) {
		kvm_err(-EINVAL, "unsupported CRm (%d) or opcode1 (%d)",
				params->CRm, params->opcode1);
		return -EINVAL;
	}

	switch (params->opcode2) {
	case 0:
		VCPU_REG(vcpu, params->rd_reg) = vcpu->arch.cp15.c13_FCSER;
		break;
	case 1:
		VCPU_REG(vcpu, params->rd_reg) = vcpu->arch.cp15.c13_CID;
		break;
	case 2:
		VCPU_REG(vcpu, params->rd_reg) = vcpu->arch.cp15.c13_TIDURW;
		break;
	case 3:
		VCPU_REG(vcpu, params->rd_reg) = vcpu->arch.cp15.c13_TIDURO;
		break;
	case 4:
		VCPU_REG(vcpu, params->rd_reg) = vcpu->arch.cp15.c13_TIDPO;
		break;
	default:
		kvm_err(-EINVAL, "unknown opcode2: %d", params->opcode2);
		return -EINVAL;
	}

	return 0;
}

static void init_coproc_params(struct kvm_vcpu *vcpu, u32 instr,
			       struct coproc_params *params)
{
	params->vcpu = vcpu;
	params->instr = instr;
	params->opcode1 = (instr >>21)  & 0x7;
	params->rd_reg = (instr >>12) & 0xf;
	params->CRn = (instr >>16) & 0xf;
	params->CRm = (instr & 0xf);
	params->opcode2 = (instr >>5)  & 0x7;
}

static int emulate_mcr(struct kvm_vcpu *vcpu, u32 instr)
{
	struct coproc_params params, *p;
	p = &params;
	init_coproc_params(vcpu, instr, p);


	switch (params.CRn) {
	case 0: /* Processor ID Codes */
		/* Not allowed to set anything in CR0 */
		kvm_msg("guest tried to write to ID register at: %08x",
				VCPU_REG(vcpu, 15));
		return 0;
	case 1: /* System configuration */
		return emulate_mcr_sysconf(p);
	case 2: /* Page table */
		return emulate_mcr_pgtable(p);
	case 3: /* Domain access control */
		return emulate_mcr_dac(p);
	case 5: /* Instruction fault status register */
		return emulate_mcr_fsr(p);
	case 6: /* Fault address register */
		return emulate_mcr_far(p);
	case 7: /* Cache management functions */
		return emulate_mcr_cache(p);
	case 8: /* MMU TLB Control */
		return emulate_mcr_mmu_tlb(p);
	case 9: /* Cache lockdown functions */
		return emulate_mcr_cache_lck(p);
	case 10: /* TLB Lockdown functions */
		KVMARM_NOT_IMPLEMENTED();
	case 13: /* Process ID Register */
		return emulate_mcr_proc_id(p);
	default:
		kvm_err(-EINVAL, "unsupported CRn: %d", params.CRn);
		return -EINVAL;
	}
}

static int emulate_mrc(struct kvm_vcpu *vcpu, u32 instr)
{
	struct coproc_params params, *p;
	p = &params;
	init_coproc_params(vcpu, instr, p);


	switch (params.CRn) {
	case 0: /* Processor ID Codes */
		return emulate_mrc_idcodes(p);
	case 1: /* System configuration */
		return emulate_mrc_sysconf(p);
	case 2: /* Page table */
		return emulate_mrc_pgtable(p);
	case 3: /* Domain access control */
		return emulate_mrc_dac(p);
	case 5: /* Instruction fault status register */
		return emulate_mrc_fsr(p);
	case 6: /* Fault address register */
		return emulate_mrc_far(p);
	case 7: /* Cache management functions */
		return emulate_mrc_cache(p);
	case 8: /* MMU TLB Control */
		kvm_err(-EINVAL, "unsupported read from TLB control register");
		return -EINVAL;
	case 9: /* Cache lockdown functions */
		return emulate_mrc_cache_lck(p);
	case 10: /* TLB Lockdown functions */
		KVMARM_NOT_IMPLEMENTED();
	case 13: /* Process ID Register */
		return emulate_mrc_proc_id(p);
	default:
		kvm_err(-EINVAL, "unsupported CRn: %d", params.CRn);
		return -EINVAL;
	}

	return 0;
}

static int emulate_mcrr(struct kvm_vcpu *vcpu, u32 instr)
{
	/* MCRR only defined in ARM v6 */
	KVMARM_NOT_IMPLEMENTED();
	return 0; /* GCC is braindead */
}

static int emulate_mrrc(struct kvm_vcpu *vcpu, u32 instr)
{
	/* MCRR only defined in ARM v6 */
	KVMARM_NOT_IMPLEMENTED();
	return 0; /* GCC is braindead */
}


/******************************************************************************
 * Data processing instructions emulation
 *****************************************************************************/

/*
 * Emulates a data instruction with the S-bit set.
 */
#define DP_INSTR_RM_SHIFT	0
#define DP_INSTR_RM_MASK	0xf
#define DP_INSTR_RS_BIT		4
#define DP_INSTR_RS_SHIFT	8
#define DP_INSTR_RS_MASK	(0xf << DP_INSTR_RS_SHIFT)
#define DP_INSTR_RD_SHIFT	12
#define DP_INSTR_RD_MASK	(0xf << DP_INSTR_RD_SHIFT)
#define DP_INSTR_RN_SHIFT	16
#define DP_INSTR_RN_MASK	(0xf << DP_INSTR_RN_SHIFT)
#define DP_INSTR_S_BIT		20
#define DP_INSTR_OPCODE_SHIFT	21
#define DP_INSTR_OPCODE_MASK	(0xf << DP_INSTR_OPCODE_SHIFT)
#define DP_INSTR_I_BIT		25
#define DP_OPCODE_MOV		0xd
#define DP_OPCODE_MVN		0xf
static int emulate_sensitive_dp_instr(struct kvm_vcpu *vcpu, u32 instr)
{
	u8 rd_num, rn_num, rs_num, rm_num, opcode;
	u32 shadow_result;
	u32 shadow_instr = instr;
	char *mode = NULL;

	if (BIT_CLEAR(instr, DP_INSTR_S_BIT))
		return -EINVAL;

	rd_num = (instr & DP_INSTR_RD_MASK) >> DP_INSTR_RD_SHIFT;
	if (rd_num != 15)
		return -EINVAL;

	rn_num = (instr & DP_INSTR_RN_MASK) >> DP_INSTR_RN_SHIFT;
	rs_num = (instr & DP_INSTR_RS_MASK) >> DP_INSTR_RS_SHIFT;
	rm_num = (instr & DP_INSTR_RM_MASK) >> DP_INSTR_RM_SHIFT;
	opcode = (instr & DP_INSTR_OPCODE_MASK) >> DP_INSTR_OPCODE_SHIFT;

	/* Clear the S bit in the shadow instruction */
	shadow_instr &= ~DP_INSTR_S_BIT;

	/* Set the output to be r1 */
	shadow_instr &= ~DP_INSTR_RD_MASK;
	shadow_instr |= 1U << DP_INSTR_RD_SHIFT;

	/* If the instr uses Rn, set Rn to r10 */
	if (opcode != DP_OPCODE_MOV && opcode != DP_OPCODE_MVN) {
		shadow_instr &= ~DP_INSTR_RN_MASK;
		shadow_instr |= 10U << DP_INSTR_RN_SHIFT;
	}

	/* If instr uses Rm, set to r9 */
	if (BIT_CLEAR(instr, DP_INSTR_I_BIT)) {
		shadow_instr &= ~DP_INSTR_RM_MASK;
		shadow_instr |= 9U;

		/* If shift is by register, set to r8 */
		if (BIT_SET(instr, DP_INSTR_RS_BIT)) {
			shadow_instr &= ~DP_INSTR_RS_MASK;
			shadow_instr |= 8U << DP_INSTR_RS_SHIFT;
		}
	}

	asm volatile ("mov r10, %[rn]\n\t"		// Load operands
		      "mov r9,  %[rm]\n\t"
		      "mov r8,  %[rs]\n\t"
		      "mov r0,  %[shadow_instr]\n\t"
		      "str r0, 1f\n\t"
		      "mov r0, #0\n\t"			// Flush prefetch buffer
		      "mcr p15, 0, r0, c7, c5, 4\n\t"
		      "mov r0, r0\n\t"
		      "1: .word 0\n\t"			// Execute shadow instr.
		      "mov %[result], r1" :		// Get result
		      [result] "=r" (shadow_result) :     // output
		      [rn] "r" (VCPU_REG(vcpu, rn_num)),  // input
		      [rm] "r" (VCPU_REG(vcpu, rm_num)),  // input
		      [rs] "r" (VCPU_REG(vcpu, rs_num)),  // input
		      [shadow_instr] "r" (shadow_instr) : // input
		      "r10", "r9", "r8", "r1", "r0");     // clobber

	VCPU_REG(vcpu, rd_num) = shadow_result;
	kvm_cpsr_write(vcpu, VCPU_SPSR(vcpu));

	switch (vcpu->arch.mode) {
		case MODE_USER: mode = "USR"; break;
		case MODE_FIQ: mode = "FIQ"; break;
		case MODE_IRQ: mode = "IRQ"; break;
		case MODE_SVC: mode = "SVC"; break;
		case MODE_ABORT: mode = "ABT"; break;
		case MODE_UNDEF: mode = "UND"; break;
		case MODE_SYSTEM: mode = "SYS"; break;
	}

	return 0;
}


/******************************************************************************
 * Load-Store instruction emulation
 *****************************************************************************/

/*
 * Must be ordered with LOADS first and WRITES afterwards
 * for easy distinction when doing MMIO.
 */
#define NUM_LD_INSTR  9
#define NUM_LS_INSTR 16
static u32 ls_instr[NUM_LS_INSTR][2] = {
	 {0x04700000, 0x0d700000} /* LDRBT */
	,{0x04300000, 0x0d700000} /* LDRT  */
	,{0x04100000, 0x0c500000} /* LDR   */
	,{0x04500000, 0x0c500000} /* LDRB  */
	,{0x000000d0, 0x0e1000f0} /* LDRD  */
	,{0x01900090, 0x0ff000f0} /* LDREX */
	,{0x001000b0, 0x0e1000f0} /* LDRH  */
	,{0x001000d0, 0x0e1000f0} /* LDRSB */
	,{0x001000f0, 0x0e1000f0} /* LDRSH */
	,{0x04600000, 0x0d700000} /* STRBT */
	,{0x04200000, 0x0d700000} /* STRT  */
	,{0x04000000, 0x0c500000} /* STR   */
	,{0x04400000, 0x0c500000} /* STRB  */
	,{0x000000f0, 0x0e1000f0} /* STRD  */
	,{0x01800090, 0x0ff000f0} /* STREX */
	,{0x000000b0, 0x0e1000f0} /* STRH  */
};

static inline int get_arm_ls_instr_index(u32 instr)
{
	return kvm_instr_index(instr, ls_instr, NUM_LS_INSTR);
}

#define NUM_LDMULT_INSTR 3
#define NUM_LSMULT_INSTR 5
static u32 lsmult_instr[NUM_LSMULT_INSTR][2] = {
	 {0x08100000, 0x0e500000} /* LDM (1) */
	,{0x08500000, 0x0e708000} /* LDM (2) */
	,{0x08508000, 0x0e708000} /* LDM (3) */
	,{0x08000000, 0x0e500000} /* STM (1) */
	,{0x08400000, 0x0e700000} /* STM (2) */
};

static inline int get_arm_lsmult_instr_index(u32 instr)
{
	return kvm_instr_index(instr, lsmult_instr, NUM_LSMULT_INSTR);
}

int kvm_ls_length(struct kvm_vcpu *vcpu, u32 instr)
{
	int index;

	index = get_arm_ls_instr_index(instr);
	if (index != INSTR_NONE) {
		if (BIT_SET(instr, INSTR_LS_TYPE_BIT)) {
			/* LS word or unsigned byte */

			if (BIT_SET(instr, INSTR_LS_BIT_B)) {
				return sizeof(unsigned char);
			} else {
				return sizeof(u32);
			}

		} else {
			/* LS halfword, doubleword or signed byte */
			u32 H = BIT_SET(instr, INSTR_LS_BIT_H);
			u32 S = BIT_SET(instr, INSTR_LS_BIT_S);
			u32 L = BIT_SET(instr, INSTR_LS_BIT_L);

			if (L && S && !H) {
				return sizeof(char);
			} else if (!L && S) {
				printk(KERN_DEBUG "WARNING: We are using double word "
						"for length. Is this an MMIO, which "
						"will be killed???\n\n\n\n");
				return 2 * sizeof(u32);
			} else {
				return sizeof(u16);
			}
		}
	}

	index = get_arm_lsmult_instr_index(instr);
	if (index != INSTR_NONE) {
		KVMARM_NOT_IMPLEMENTED();
	}

	BUG();
	return 0; /* GCC is braindead */
}

int kvm_ls_is_write(struct kvm_vcpu *vcpu, u32 instr)
{
	int index;

	index = get_arm_ls_instr_index(instr);
	if (index != INSTR_NONE) {
		if (index < NUM_LD_INSTR)
			return 0;
		else
			return 1;
	}

	index = get_arm_lsmult_instr_index(instr);
	if (index != INSTR_NONE) {
		if (index < NUM_LDMULT_INSTR)
			return 0;
		else
			return 1;
	}

	BUG();
	return 0; /* GCC is braindead */
}

int kvm_ls_get_rd(struct kvm_vcpu *vcpu, u32 instr)
{
	int index;

	index = get_arm_ls_instr_index(instr);
	if (index != INSTR_NONE) {
		return (instr & INSTR_LS_RD_MASK) >> INSTR_LS_RD_SHIFT;
	}

	index = get_arm_lsmult_instr_index(instr);
	if (index != INSTR_NONE) {
		return -EINVAL;
	}

	BUG();
	return 0; /* GCC is braindead */
}

int kvm_ls_get_rn(struct kvm_vcpu *vcpu, u32 instr)
{
	int ls_indx, lsmult_indx;

	ls_indx = get_arm_ls_instr_index(instr);
	lsmult_indx = get_arm_lsmult_instr_index(instr);
	if (ls_indx != INSTR_NONE || lsmult_indx != INSTR_NONE) {
		return (instr & INSTR_LS_RN_MASK) >> INSTR_LS_RN_SHIFT;
	}

	BUG();
	return 0; /* GCC is braindead */
}

static inline gva_t ls_word_calc_offset(struct kvm_vcpu *vcpu, u32 instr)
{
	int offset;

	if (CHECK_BITS(instr, OFFSET_IMM_MASK, OFFSET_IMM_VALUE)) {
		/* Immediate offset/index */
		offset = instr & INSTR_LS_OFFSET12_MASK;

		if (!BIT_SET(instr, INSTR_LS_BIT_U)) {
			offset = -offset;
		}
	}

	if (CHECK_BITS(instr, OFFSET_REG_MASK, OFFSET_REG_VALUE)) {
		/* Register offset/index */
		u8 rm = instr & INSTR_LS_RM_MASK;
		offset = VCPU_REG(vcpu, rm);

		if (!BIT_SET(instr, INSTR_LS_BIT_P))
			offset = 0;
	}

	if (CHECK_BITS(instr, OFFSET_SCALE_MASK, OFFSET_SCALE_VALUE)) {
		/* Scaled register offset */
		int asr_test;
		u8 rm = instr & INSTR_LS_RM_MASK;
		u8 shift = (instr & SCALE_SHIFT_MASK) >> SCALE_SHIFT_SHIFT;
		u32 shift_imm = (instr & SCALE_SHIFT_IMM_MASK)
				>> SCALE_SHIFT_IMM_SHIFT;
		offset = VCPU_REG(vcpu, rm);

		switch (shift) {
		case SCALE_SHIFT_LSL:
			offset = offset << shift_imm;
			break;
		case SCALE_SHIFT_LSR:
			if (shift_imm == 0)
				offset = 0;
			else
				offset = ((u32)offset) >> shift_imm;
			break;
		case SCALE_SHIFT_ASR:
			/* Test that the compiler used arithmetic right shift
			 * for signed values. */
			asr_test = 0xffffffff;
			BUG_ON((asr_test >> 2) >= 0);
			if (shift_imm == 0) {
				if (BIT_SET(offset, 31))
					offset = 0xffffffff;
				else
					offset = 0;
			} else {
				offset = offset >> shift_imm;
			}
			break;
		case SCALE_SHIFT_ROR_RRX:
			/* Test that the compiler used arithmetic right shift
			 * for signed values. */
			asr_test = 0xffffffff;
			BUG_ON((asr_test >> 2) >= 0);
			if (shift_imm == 0) {
				u32 C = BIT_SET(vcpu->arch.cpsr, PSR_BIT_C);
				offset = (C << 31) | offset >> 1;
			} else {
				offset = ror32(offset, shift_imm);
			}
			break;
		}

		if (BIT_SET(instr, INSTR_LS_BIT_U))
			return offset;
		else
			return -offset;
	}

	if (BIT_SET(instr, INSTR_LS_BIT_U))
		return offset;
	else
		return -offset;

	BUG();
}

int kvm_ls_get_address(struct kvm_vcpu *vcpu, u32 instr)
{
	int index;
	u8 rn;
	gva_t base;

	index = get_arm_ls_instr_index(instr);
	if (index != INSTR_NONE) {
		rn = (instr & INSTR_LS_RN_MASK) >> INSTR_LS_RN_SHIFT;
		base = VCPU_REG(vcpu, rn);
		if (BIT_SET(instr, INSTR_LS_TYPE_BIT)) {
			/* LS word or unsigned byte */
			if (BIT_CLEAR(instr, INSTR_LS_BIT_P))
				return base;
			else
				return base + ls_word_calc_offset(vcpu, instr);
		} else {
			/* LS halfword, doubleword or signed byte */
			KVMARM_NOT_IMPLEMENTED();
		}
	}

	index = get_arm_lsmult_instr_index(instr);
	if (index != INSTR_NONE) {
		rn = (instr & INSTR_LSM_RN_MASK) >> INSTR_LSM_RN_SHIFT;
		return VCPU_REG(vcpu, rn);
			
	}

	BUG();
	return 0; /* GCC is braindead */
}

/*
 * If a Load/Store (not multiple) instruction performs a writeback
 * to the base register from either postfixing with a ! (the W bit)
 * or because the addressing mode is [Rn], #offset, then a value has
 * to be written back to the base register Rn.
 *
 * Note, this function can safely be called for instructions, which
 * do not do any writeback, as it will be ignored then.
 *
 * param vcpu:  The virtual cpu struct
 * param instr: The load/store instruction to emulate
 */
int kvm_ls_emulate_writeback(struct kvm_vcpu *vcpu, u32 instr)
{
	int rn;
	u32 offset;

	if (BIT_CLEAR(instr, INSTR_LS_BIT_P) || BIT_SET(instr, INSTR_LS_BIT_W)) {
		rn = kvm_ls_get_rn(vcpu, instr);
		offset = ls_word_calc_offset(vcpu, instr);
		VCPU_REG(vcpu, rn) += offset;
	}

	return 0;
}

static inline int ls_mult_copy_register(struct kvm_vcpu *vcpu, u32 instr,
				 int reg_index, gva_t *guest_addr) 
{
	int ret;
	hva_t host_addr;
	u32 *reg;

	//printk(KERN_DEBUG "LSM guest_addr: 0x%08x\n", (unsigned int)(*guest_addr));

	// TODO: Check if the guest has permission to this address!
	host_addr = gva_to_hva(vcpu, *guest_addr, 0);
	if (kvm_is_error_hva(host_addr))
		return -EFAULT;

	/* Use user-mode registers if S-bit is set and
	 * r15 is not in the registers list. */
	if (BIT_SET(instr, INSTR_LSM_BIT_S) &&
	    BIT_CLEAR(instr, 15)) {
		reg = &(vcpu->arch.regs[reg_index]);
	} else {
		reg = kvm_vcpu_reg(&vcpu->arch, reg_index);
	}

	/* Read/Write operation */
	if (BIT_SET(instr, INSTR_LSM_BIT_L))
		ret = copy_from_user(reg, (u32 *)host_addr, sizeof(u32));
	else
		ret = copy_to_user((u32 *)host_addr, reg, sizeof(u32));

	if (ret)
		return -EFAULT;

	*guest_addr += 4;
	return 0;
}

static int emulate_ls_mult(struct kvm_vcpu *vcpu, u32 instr)
{
	int i;
	int ret;
	gva_t guest_base, guest_addr;
	u32 register_count, register_list;
	u8 rn = (instr & INSTR_LSM_RN_MASK) >> INSTR_LSM_RN_SHIFT;

	/* Check is S bit is set in USER og SYSTEM mode */
	if (BIT_SET(instr, INSTR_LSM_BIT_S) &&
	    (vcpu->arch.mode == MODE_USER || vcpu->arch.mode == MODE_SYSTEM)) {
		vcpu->arch.exception_pending |= EXCEPTION_UNDEFINED;
		return 0;
	}

	/* Check that W bit is clear if S bit set and r15 not in register list */
	if (BIT_SET(instr, INSTR_LSM_BIT_S) && BIT_SET(instr, INSTR_LSM_BIT_W) &&
		BIT_CLEAR(instr, 15)) {
		vcpu->arch.exception_pending |= EXCEPTION_UNDEFINED;
		return 0;
	}

	/* Count number of registers to load/store */
	register_list = instr & INSTR_LSM_REG_MASK;
	for (register_count = 0; register_list != 0; register_count++)
		register_list &= register_list - 1;

	/* Get base address and adjust for D<B/A> or IB addressing modes. */
	guest_base = kvm_ls_get_address(vcpu, instr);
	if (BIT_CLEAR(instr, INSTR_LSM_BIT_U)) {
		/* Loading downwards (decrement) */
		guest_addr = guest_base - (4 * register_count);
		if (BIT_CLEAR(instr, INSTR_LSM_BIT_P))
			guest_addr += 4;
	} else {
		/* Loading upwards (increment) */
		if (BIT_SET(instr, INSTR_LSM_BIT_P))
			guest_addr = guest_base + 4;
		else
			guest_addr = guest_base;

	}

	/* Load/Store each register with bit set in register list */
	for (i = 0; i < 16; i++) {
		if (BIT_SET(instr, i)) {
			ret = ls_mult_copy_register(vcpu, instr, i, &guest_addr);
			if (ret)
				return ret;
		}
	}

	/* Do possible write back to Rn register */
	if (BIT_SET(instr, INSTR_LSM_BIT_W)) {
		if (BIT_SET(instr, INSTR_LSM_BIT_U))
			VCPU_REG(vcpu, rn) += register_count * 4;
		else
			VCPU_REG(vcpu, rn) -= register_count * 4;
	}

	/* Possibly write SPSR to CPSR */
	if (BIT_SET(instr, INSTR_LSM_BIT_L) && BIT_SET(instr, INSTR_LSM_BIT_S) 
		&& BIT_SET(instr, 15)) {
		kvm_cpsr_write(vcpu, VCPU_SPSR(vcpu));
	}

	/* If not a branch, skip the trap and the instruction upon return */
	if (BIT_CLEAR(instr, 15)) {
		vcpu->arch.regs[15] += 8;
	}

	return 0;
}


extern void print_guest_mapping(struct kvm_vcpu *vcpu, gva_t gva);
static int emulate_ls_with_trans(struct kvm_vcpu *vcpu, u32 instr)
{
	struct map_info map_info;
	gfn_t tmp_gfn;
	int fault;
	u8 subpage, ap;
	u8 domain_type;
	u8 write = kvm_ls_is_write(vcpu, instr);
	gva_t gva = kvm_ls_get_address(vcpu, instr);

	/*
	printk(KERN_DEBUG "Emualting ls with Translation:\n");
	printk(KERN_DEBUG "   instr: 0x%08x\n", instr);
	printk(KERN_DEBUG "     gva: 0x%08x\n", gva);
	*/

	fault = gva_to_gfn(vcpu, gva, &tmp_gfn, 1, &map_info);
	if (fault < 0)
		return fault;
	
	/* Let the PC point to the sens. instr. no matter if we raise excp. or
	 * execute it natively. */
	vcpu->arch.regs[15] += 4;

	if (fault) {
		// XXX The stored PC will point to the sensitiveinstr.
		// at this point which is good for the instr., but the
		// guest handler may return directly to the function and
		// we won't catch that access again...
		kvm_generate_mmu_fault(vcpu, gva, fault, map_info.domain_number);
		return 0;
	}


	domain_type = VCPU_DOMAIN_VAL(vcpu, map_info.domain_number);
	if (write && domain_type == DOMAIN_CLIENT) {
		subpage = (gva >> 10) & 0x3;
		ap = (map_info.ap >> (2*subpage)) & 0x3;
		if (kvm_decode_ap(vcpu, ap, 1) != KVM_AP_RDWRITE) {
			kvm_generate_mmu_fault(vcpu, gva, FSR_PERM_PAGE, map_info.domain_number);
		}
	}

	return 0;
}


#define MSR_R_BIT 22
static int emulate_mrs(struct kvm_vcpu *vcpu, u32 instr)
{
	u32 reg = (instr >> 12) & 0xf;
	if (BIT_SET(instr, MSR_R_BIT))
		VCPU_REG(vcpu, reg) = VCPU_SPSR(vcpu);
	else
		VCPU_REG(vcpu, reg) = vcpu->arch.cpsr;
	
	vcpu->arch.regs[15] += 8;
	return 0;
}

/*
 * Define the bitmasks used for by the hardware to execute the
 * MSR instructions. See the ARM DDI 0100I - A4-77.
 */
static u32 msr_bitmasks[5][4] = {
      /* UnallocMask   UserMask    PrivMask    StateMask     Arch.      */
	 {0x0FFFFF20, 0xF0000000, 0x000001DF, 0x00000000} /* 4          */
	,{0x0FFFFF00, 0xF0000000, 0x000001DF, 0x00000020} /* 4T, 5T     */
	,{0x07FFFF00, 0xF8000000, 0x000001DF, 0x00000020} /* 5TE, 5TExP */
	,{0x06FFFF00, 0xF8000000, 0x000001DF, 0x01000020} /* 5TEJ       */
	,{0x06F0FC00, 0xF80F0200, 0x000001DF, 0x01000020} /* 6          */
};

static int get_msr_bitmask_table_index(void)
{
	int cpu_arch = cpu_architecture();
	switch (cpu_arch) {
	case CPU_ARCH_ARMv4:
		return 0;
	case CPU_ARCH_ARMv4T:
	case CPU_ARCH_ARMv5:
	case CPU_ARCH_ARMv5T:
		return 1;
	case CPU_ARCH_ARMv5TE:
		return 2;
	case CPU_ARCH_ARMv5TEJ:
		return 3;
	case CPU_ARCH_ARMv6:
		return 4;
	default:
		return -EINVAL;
	}
}


#define MSR_IMM_BIT		25
#define MSR_FMASK_C_BIT 	16
#define MSR_FMASK_X_BIT 	17
#define MSR_FMASK_S_BIT 	18
#define MSR_FMASK_F_BIT 	19

/*
 * Modelled after the ARM arm (DDI 0100I) - A4-77.
 */
static int emulate_msr(struct kvm_vcpu *vcpu, u32 instr)
{
	u32 unalloc_mask, user_mask, priv_mask, state_mask;
	u32 operand, shift, byte_mask, mask;
	int tbl_idx;

	tbl_idx = get_msr_bitmask_table_index();
	if (tbl_idx < 0)
		return tbl_idx;

	unalloc_mask = msr_bitmasks[tbl_idx][0];
	user_mask =    msr_bitmasks[tbl_idx][1];
	priv_mask =    msr_bitmasks[tbl_idx][2];
	state_mask =   msr_bitmasks[tbl_idx][3];

	if (BIT_SET(instr, MSR_IMM_BIT)) {
		operand = (instr & 0xff);
		shift = ((instr >> 8) & 0xf) * 2;
		if (shift)
			operand = (operand >> shift) | (operand << (32 - shift));
	} else {
		operand = VCPU_REG(vcpu, instr & 0xf);
	}

	byte_mask = (BIT_SET(instr, MSR_FMASK_C_BIT) ? PSR_c : 0) | 
		    (BIT_SET(instr, MSR_FMASK_X_BIT) ? PSR_x : 0) | 
		    (BIT_SET(instr, MSR_FMASK_S_BIT) ? PSR_s : 0) | 
		    (BIT_SET(instr, MSR_FMASK_F_BIT) ? PSR_f : 0);

	if (BIT_CLEAR(instr, MSR_R_BIT)) {
		/* CPSR */
		if (VCPU_MODE_PRIV(vcpu)) {
			if ((operand & state_mask) != 0)
				return -EINVAL;
			else
				mask = byte_mask & (user_mask | priv_mask);
		} else {
			mask = byte_mask & user_mask;
		}
		kvm_cpsr_write(vcpu, (vcpu->arch.cpsr & ~mask)
				     | (operand & mask));
	} else {
		/* SPSR */
		if (!MODE_HAS_SPSR(vcpu))
			return -EINVAL;
		mask = byte_mask & (user_mask | priv_mask | state_mask);
		VCPU_SPSR(vcpu) = (VCPU_SPSR(vcpu) & ~mask) | (operand & mask);
	}

	vcpu->arch.regs[15] += 8;
	return 0;
}


#define NUM_DP_INSTR 12
static u32 privdp_instr[NUM_DP_INSTR][2] = {
	{0x00b0f000,0x0de0f000} /* ADC     */
       ,{0x0090f000,0x0de0f000} /* ADD     */
       ,{0x0010f000,0x0de0f000} /* AND     */
       ,{0x01d0f000,0x0de0f000} /* BIC     */
       ,{0x0030f000,0x0de0f000} /* EOR     */
       ,{0x01b0f000,0x0de0f000} /* MOV     */
       ,{0x01f0f000,0x0de0f000} /* MVN     */
       ,{0x0190f000,0x0de0f000} /* ORR     */
       ,{0x0070f000,0x0de0f000} /* RSB     */
       ,{0x00f0f000,0x0de0f000} /* RSC     */
       ,{0x00d0f000,0x0de0f000} /* SBC     */
       ,{0x0050f000,0x0de0f000} /* SUB     */
};

static inline int get_arm_privdp_instr_index(u32 instr)
{
	return kvm_instr_index(instr, privdp_instr, NUM_DP_INSTR);
}

#define NUM_PSR_INSTR 5
static u32 psr_instr[NUM_PSR_INSTR][2] = {
	 {0x01000000, 0x0fb00000} /* MRS              */
	,{0x03200000, 0x0fb00000} /* MSR (immediate)  */
	,{0x01200000, 0x0fb000f0} /* MSR (register)   */
	,{0xf1000000, 0xfff10020} /* CPS              */
	,{0xf1010000, 0xffff00f0} /* SETEND           */
};

static inline int get_arm_psr_instr_index(u32 instr)
{
	return kvm_instr_index(instr, psr_instr, NUM_PSR_INSTR);
}

#define CPS_IMOD_MASK	0x000c0000
#define CPS_IMOD_EN	0x00080000
#define CPS_IMOD_DIS	0x000c0000
#define CPS_IBITS_MASK	0x000001c0
#define CPS_MMOD_MASK	0x000c0000
#define CPS_MBITS_MASK	0x0000001f
static int emulate_cps(struct kvm_vcpu *vcpu, u32 instr)
{
	struct kvm_vcpu_arch *arch = &vcpu->arch;

	if ((instr & CPS_IMOD_MASK) == CPS_IMOD_EN) {
		/* Enable interrupts (unamsk) */ 
		kvm_cpsr_write(vcpu, arch->cpsr & ~(instr & CPS_IBITS_MASK));
	} else if ((instr & CPS_IMOD_MASK) == CPS_IMOD_DIS) {
		/* Disable interrupts (mask) */
		kvm_cpsr_write(vcpu, arch->cpsr | (instr & CPS_IBITS_MASK));
	}

	if ((instr & CPS_MMOD_MASK) > 0) {
		/* Set mode */ 
		kvm_cpsr_write(vcpu, (arch->cpsr & ~MODE_MASK)
				     | (instr & CPS_MBITS_MASK));
	} 

	vcpu->arch.regs[15] += 8;
	return 0;
}
