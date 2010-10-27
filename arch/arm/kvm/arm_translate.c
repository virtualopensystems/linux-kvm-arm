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

#include <linux/list.h>
#include <linux/string.h>
#include <asm/kvm_arm.h>
#include <asm/uaccess.h>
#include <asm/kvm_mmu.h>

#define COND_MASK       	0xf0000000
#define COND_ALWAYS     	0xe0000000
#define BRANCH_IMM      	0x00ffffff
#define BRANCH_LINK     	0x01000000
#define COND_SWI   		0x0F000000
#define UNCOND_SWI 		0xEF000000 

#define BRANCH_CONT		0
#define BRANCH_UNCOND		1
#define BRANCH_UNPRED		2

#define EXEC_ALWAYS(instr)	((instr & COND_MASK) == COND_ALWAYS)


/* Identifiers for instructions that are translated to SWI instructions. */
/* Usermode reg instructions */
#define BRANCH_INSTR_ADC       0
#define BRANCH_INSTR_ADD       1  
#define BRANCH_INSTR_AND       2  
#define BRANCH_INSTR_BIC       3  
#define BRANCH_INSTR_EOR       4  
#define BRANCH_INSTR_MOV       5  
#define BRANCH_INSTR_MVN       6  
#define BRANCH_INSTR_ORR       7  
#define BRANCH_INSTR_RSB       8  
#define BRANCH_INSTR_RSC       9   
#define BRANCH_INSTR_SBC      10   
#define BRANCH_INSTR_SUB      11   
#define BRANCH_INSTR_CPY      12   
#define BRANCH_INSTR_LDR      13  
#define BRANCH_INSTR_B        14
#define BRANCH_INSTR_BL       15
#define BRANCH_INSTR_BLX      16
#define BRANCH_INSTR_BX       17
#define BRANCH_INSTR_LDM_1    18  
#define BRANCH_INSTR_LDM_3    19
#define BRANCH_INSTR_LDM_2    20

#define TRANS_INSTR_NONE     -1
#define TRANS_INSTR_LDRBT    0
#define TRANS_INSTR_LDRT     1
#define TRANS_INSTR_STM_2    2
#define TRANS_INSTR_STRBT    3
#define TRANS_INSTR_STRT     4
#define TRANS_INSTR_CPS      5
#define TRANS_INSTR_MRS      6
#define TRANS_INSTR_MSR_Imm  7
#define TRANS_INSTR_MSR_Reg  8
#define TRANS_INSTR_RFE      9 
#define TRANS_INSTR_SRS      10
#define TRANS_INSTR_LDM_3    11
#define TRANS_INSTR_LDM_2    12
		




#ifdef KVMARM_BIN_TRANSLATE 

static int get_trans_instr_index(u32 instr)
{
	return get_instr_index(instr, trans_instr, NUM_TRANS_INSTR);
}


static int get_branch_instr_index(u32 instr)
{
	return get_instr_index(instr, branch_instr, NUM_BRANCH_INSTR);
}

#define NUM_BRANCH_INSTR     21
/*
 * XXX This table hold all bits to be set in first column
 * and all bits to be cleared in second column. Must be changed
 * to use values in first column and mask in seconds column
 * to work with get_instr_index(...)
 */
static u32 branch_instr[NUM_BRANCH_INSTR][2] = {
                {0x00A0F000,0x0D400000} /* ADC     */
               ,{0x0080F000,0x0D600000} /* ADD     */
               ,{0x0000F000,0x0DE00000} /* AND     */
               ,{0x01C0F000,0x0C200000} /* BIC     */
               ,{0x0020F000,0x0DC00000} /* EOR     */
               ,{0x01A0F000,0x0C400000} /* MOV     */
               ,{0x01E0F000,0x0C000000} /* MVN     */
               ,{0x0180F000,0x0C600000} /* ORR     */
               ,{0x0060F000,0x0D800000} /* RSB     */
               ,{0x00E0F000,0x0D000000} /* RSC     */
               ,{0x00C0F000,0x0D200000} /* SBC     */
               ,{0x0040F000,0x0DA00000} /* SUB     */
               ,{0x01A0F000,0x0E5F0FF0} /* CPY     */
               ,{0x0410F000,0x08400000} /* LDR     */
               ,{0x0A000000,0x05000000} /* B       */
               ,{0x0B000000,0x04000000} /* BL      */
               ,{0x012FFF30,0x0ED000C0} /* BLX     */
               ,{0x012FFF10,0x0ED000E0} /* BX      */
               ,{0x08108000,0x06400000} /* LDM_1   */
               ,{0x08508000,0x06000000} /* LDM_3   */
               ,{0x08500000,0x06208000} /* LDM_2   */
};

#define NUM_TRANS_INSTR	     13 
/*
 * XXX This table hold all bits to be set in first column
 * and all bits to be cleared in second column. Must be changed
 * to use values in first column and mask in seconds column
 * to work with get_instr_index(...)
 */
static u32 trans_instr[NUM_TRANS_INSTR][2] = {
                {0x04700000,0x09000000} /* LDRBT   */
               ,{0x04300000,0x09400000} /* LDRT    */
               ,{0x08400000,0x06300000} /* STM_2   */
               ,{0x04600000,0x09100000} /* STRBT   */
               ,{0x04200000,0x09500000} /* STRT    */
               ,{0xF1000000,0x0EF1FE20} /* CPS     */
               ,{0x010F0000,0x0EB00FFF} /* MRS     */
               ,{0x0320F000,0x0C900000} /* MSR_Imm */
               ,{0x0120F000,0x0E900FF0} /* MSR_Reg */
               ,{0xF8100A00,0x0640F5FF} /* RFE     */
               ,{0xF84D0500,0x0612FAE0} /* SRS     */
               ,{0x08508000,0x06000000} /* LDM_3   */
               ,{0x08500000,0x06208000} /* LDM_2   */
};


static int add_translated_block(struct kvm_vcpu *vcpu, gva_t start, gva_t end)
{
        struct kvm_basic_block *bb;
        bb = kmalloc(sizeof(struct kvm_basic_block), GFP_KERNEL);
        if (!bb)
		return -ENOMEM;
        bb->start_addr = start;
        bb->end_addr = end;

	list_add(&bb->list, &vcpu->arch.trans_head);
	return 0;
}

static int already_translated(struct kvm_vcpu *vcpu, gva_t addr)
{
        struct kvm_basic_block *bb;

	list_for_each_entry(bb, &vcpu->arch.trans_head, list) {
		if (bb->start_addr <= addr && bb->end_addr >= addr)
			return 1;
	}
	
	return 0;
}

int check_branch(gva_t addr, u32 instr, struct list_head *trans_list)
{
	int op;
	int dest_addr, imm;
	struct kvm_basic_block *bb;

	op = get_branch_instr_index(instr);
	if (op == TRANS_INSTR_NONE) 
		return BRANCH_CONT;

	/* Branch instruction */
	switch (op) {
	case BRANCH_INSTR_B:
	case BRANCH_INSTR_BL:
	case BRANCH_INSTR_BX:
	case BRANCH_INSTR_BLX:
		/* Calculate destination address */
		imm = (instr & BRANCH_IMM);
		if ((imm >> 23) == 1) /* sign extend */
			imm = imm | 0xff000000;
		dest_addr = (imm << 2) + addr + 0x8;

		bb = kmalloc(sizeof(struct kvm_basic_block), GFP_KERNEL);
		if (!bb)
			return -ENOMEM;

		bb->start_addr = dest_addr;
		bb->branch_addr = addr;
		list_add(&bb->list, trans_list);
		
		/*
		printk("  -- branch detected at 0x%08x to 0x%08x\n",
			(unsigned int)addr,
			(unsigned int)dest_addr);
			*/

		/* Check unconditional branch */
		if (EXEC_ALWAYS(instr) && ((instr & BRANCH_LINK) == 0x0))
			return BRANCH_UNCOND;

		return BRANCH_CONT;
	default:
		return BRANCH_UNPRED;
	}
}

int trap_on_addr(struct kvm_vcpu *vcpu, u32 addr)
{
	u32 instr;
	u32 trans_instr;
	struct kvm_trans_orig *orig;
	hva_t host_addr;
	int ret;

	orig = kmalloc(sizeof(struct kvm_trans_orig), GFP_KERNEL);
	if (!orig)
		return -ENOMEM;
	/*
	 * Get host address and retrieve the original instruction
	 */
	host_addr = gva_to_hva(vcpu, addr);
	ret = copy_from_user(&instr, (void *)host_addr, sizeof(u32));
	if (ret)
		return -EFAULT;

	orig->addr = addr;
	orig->instr = instr;
	list_add(&orig->list, &vcpu->arch.trans_orig);

	/*
	 * All instructions can be turned into SWI by this operation
	 */
	trans_instr = instr | COND_SWI; 

	ret = copy_to_user((void *)host_addr, &trans_instr, sizeof(u32));
	if (ret) 
		return -EFAULT;

	return 0;
}

int translate_basic_block(struct kvm_vcpu *vcpu,
		 	  struct kvm_basic_block *bb,
			  struct list_head *bb_list,
			  gva_t init_addr)
{
	u32 instr;
	hva_t host_addr;
	gva_t addr;
	gva_t b_addr;
	int branch;
	int ret;
	int op;

	addr = bb->start_addr;
	b_addr = bb->branch_addr;
	do {
		host_addr = gva_to_hva(vcpu, addr);
		ret = copy_from_user(&instr, (void *)host_addr, sizeof(u32));
		if (ret && bb->branch_addr == init_addr)
			goto init_instr_stream_fault;
		else if (ret && already_translated(vcpu, bb->branch_addr))
			goto trap_instr_stream_fault;
		else if (ret) {
			if ((ret = trap_on_addr(vcpu, addr)))
				return ret;
		}

		branch = check_branch(addr, instr, bb_list);
		if (branch < 0)
			return branch;
		else if (branch == BRANCH_UNCOND) {
			break;
		}

		op = get_trans_instr_index(instr);
		if (op != TRANS_INSTR_NONE || branch == BRANCH_UNPRED) {
			ret = trap_on_addr(vcpu, addr);
			if (ret)
				return ret;
		}

		/* Unconditional branch - stop executing */
		addr += 4;
	} while (branch == BRANCH_CONT);

	/*
	printk(KERN_DEBUG "Translated from 0x%08x to 0x%08x\n\n",
			(unsigned int)bb->start_addr,
			(unsigned int)addr);
			*/

	return 0;
init_instr_stream_fault:
	KVMARM_NOT_IMPLEMENTED();
trap_instr_stream_fault:
	KVMARM_NOT_IMPLEMENTED();
}

int kvmarm_translate(struct kvm_vcpu *vcpu, gva_t init_addr)
{
	struct kvm_basic_block *bb;
	struct list_head head;
	gva_t addr;
	int ret;

	INIT_LIST_HEAD(&head);
	bb = kmalloc(sizeof(struct kvm_basic_block), GFP_KERNEL);
	if (!bb)
		return -ENOMEM;
	bb->start_addr = init_addr;
	bb->branch_addr = init_addr;
	list_add(&bb->list, &head);

	while (!list_empty(&head)) {
		bb = list_entry(head.next, struct kvm_basic_block, list);
		addr = bb->start_addr;
		if (!already_translated(vcpu, addr)) {
			/*
			printk(KERN_DEBUG "Starting translation at 0x%08x\n",
					(unsigned int) addr);
					*/

			ret = translate_basic_block(vcpu, bb, &head, init_addr);
			if (ret)
				return ret;
			ret = add_translated_block(vcpu, bb->start_addr, addr);
			if (ret < 0)
				return ret;
		}
		list_del(&bb->list);
		kfree(bb);	
	}

	return 0;
}

u32 get_orig_instr(struct kvm_vcpu *vcpu, gva_t addr)
{
	hva_t host_addr;
	u32 instr;
        struct kvm_trans_orig *orig;

	/*printk(KERN_DEBUG "Checking translation table for 0x%08x...\n",
			addr);*/
	list_for_each_entry(orig, &vcpu->arch.trans_orig, list) {
		/* printk(KERN_DEBUG " - orig: 0x%08x\n", orig->addr); */
		if (orig->addr == addr)
			return orig->instr;
	}

	host_addr = gva_to_hva(vcpu, addr);
	instr = *(u32*)host_addr;
	return instr;
}

#endif
