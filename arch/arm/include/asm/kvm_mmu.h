
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
#ifndef __ARM_KVM_ARM_MMU_H__
#define __ARM_KVM_ARM_MMU_H__

#define KVM_SPECIAL_DOMAIN 15

#define KVM_AP_NONE    		0
#define KVM_AP_RDONLY  		1
#define KVM_AP_RDWRITE 		2

#define KVM_MEM_EXEC    	0
#define KVM_MEM_NOEXEC  	1

#define L1_TYPE_MASK          0x3
#define L1_TYPE_FAULT         0x0
#define L1_TYPE_COARSE        0x1
#define L1_TYPE_SECTION       0x2

/*
 * Detailed info about a guest page mapping
 */
struct map_info {
	u8 domain_number;
	u8 ap;
};

/*
 * Address space translation funcitons
 */
int gva_to_gfn(struct kvm_vcpu *vcpu, gva_t gva, gfn_t *gfn, u8 uaccess,
	       struct map_info *map_info);
hva_t gva_to_hva(struct kvm_vcpu *vcpu, gva_t gva, u8 uaccess);

/*
 * Shadow page tables
 */
typedef struct kvm_pgd kvm_pgd;
typedef struct kvm_cl2_tbl kvm_cl2_tbl; //Coarse L2 table


u32*  kvm_alloc_l1_shadow(struct kvm_vcpu *vcpu);
int   kvm_init_l1_shadow(struct kvm_vcpu * vcpu, u32 * pgd);
void  kvm_free_l1_shadow(struct kvm_vcpu * vcpu, u32 ** pgdp);
int __map_gva_to_pfn(struct kvm_vcpu *vcpu, u32 *pgd, gva_t gva, pfn_t pfn,
		     u8 domain, u8 ap, u8 exec);
int   map_gva_to_pfn(struct kvm_vcpu *vcpu, u32 *pgd, gva_t gva, pfn_t pfn,
		     u8 domain, u8 priv_ap, u8 user_ap, u8 exec);
int   unmap_gva(u32 *pgd, gva_t gva);
int   unmap_gva_section(u32 *pgd, gva_t gva);
int   kvm_update_special_region_ap(struct kvm_vcpu *vcpu, u32 *pgd, u8 domain);
int   kvm_restore_low_vector_domain(struct kvm_vcpu *vcpu, u32 *pgd);
int   kvm_switch_host_vectors(struct kvm_vcpu *vcpu, int high);
void  dump_l1_pgtable(struct kvm_vcpu *vcpu);

/*
 * Emulated MMU fault functionality
 */
void kvm_generate_mmu_fault(struct kvm_vcpu *vcpu, gva_t fault_addr,
			    u32 source, u8 domain);

/*
 * return 1 if MMU is enabled on vcpu and 0 otherwise
 */
static inline int kvm_mmu_enabled(struct kvm_vcpu *vcpu)
{
	return (vcpu->arch.cp15.c1_CR & 0x1);
}

/*
 * Decode access permissions.
 *
 * @vcpu:    The virtual cpu struct pointer
 * @ap:      The access permission bits
 * @uaccess: Return user access permissions even if VCPU is in provoleged mode
 *
 * Returns: KVM_AP_NONE, KVM_AP_RDONLY or KVM_AP_RDWRITE
 */
static inline int kvm_decode_ap(struct kvm_vcpu *vcpu, u8 ap, u8 uaccess)
{
	u8 s_bit = vcpu->arch.cp15.c1_CR & (1 << 8);
	u8 r_bit = vcpu->arch.cp15.c1_CR & (1 << 9);

	if (s_bit || r_bit)
		printk(KERN_DEBUG "Warning: Guest has S or R bit set!!!\n");

	if (ap == 0x0) {
		if (s_bit == 0 && r_bit == 0) {
			return KVM_AP_NONE;
		} else if (s_bit == 1 && r_bit == 0) {
			if (uaccess)
				return KVM_AP_NONE;
			else
				return KVM_AP_RDONLY;
		} else if (s_bit == 0 && r_bit == 1) {
			return KVM_AP_RDONLY;
		} else if (s_bit == 1 && r_bit == 1) {
			printk(KERN_WARNING "KVM: Decoding unpredictable AP bits!\n");
			return KVM_AP_NONE;
		}
	} else if (uaccess) {
		switch (ap) {
		case 0x1:
			return KVM_AP_NONE;
		case 0x2:
			return KVM_AP_RDONLY;
		case 0x3:
			return KVM_AP_RDWRITE;
		}
	} else if (!uaccess) {
		return KVM_AP_RDWRITE;
	}

	BUG();
	return 0;
}

/*
 * This function expects a valid set of access permissions for the
 * shadow page table and returns the corresponding AP bits.
 */
static inline u8 calc_aps(u8 priv, u8 user)
{
	if (priv == KVM_AP_NONE && user == KVM_AP_NONE) {
		return 0x0;
	} else if (user == KVM_AP_NONE) {
		return 0x1;
	} else if (user == KVM_AP_RDONLY) {
		return 0x2;
	} else if (user == KVM_AP_RDWRITE) {
		return 0x3;
	} else {
		BUG();
	}
}

/*
 * Convert guest AP's to corresponding shadow page table AP's based onthe
 * current VCPU mode.
 *
 * vcpu: Pointer to the virtual CPU struct
 *   ap: The set of four APs each denoting the AP for each subpage
 */
static inline u8 convert_guest_to_shadow_ap(struct kvm_vcpu *vcpu, u8 ap)
{
	u8 i, guest_mode_idx;
	u8 old_ap;

	/*
	 * Below is a table, indexed by the guest page table access permissions
	 * and with the first column gives shadow AP's if the guest is in
	 * user mode and the second column gives shadow AP's if the guest is in
	 * priv. mode.
	 */
	u8 ap_table[4][2] = {
		{0x1, 0x1},	// Guest user: NA, Guest priv: NA
		{0x1, 0x3},	// Guest user: NA, Guest priv: RW
		{0x2, 0x3},	// Guest user: RO, Guest priv: RW
		{0x3, 0x3}	// Guest user: RO, Guest priv: RW
	};

	guest_mode_idx = VCPU_MODE_PRIV(vcpu) ? 1 : 0;

	for (i = 0; i < 4; i++) {
		old_ap = (ap >> (i*2)) & 0x3;
		ap &= ~(0x3 << (i*2));
		ap |= (ap_table[old_ap][guest_mode_idx]) << (i*2);
	}

	return ap;
}



#endif /* __ARM_KVM_ARM_MMU_H__ */
