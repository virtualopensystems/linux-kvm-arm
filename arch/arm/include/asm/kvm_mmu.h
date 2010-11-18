
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

#define D_CACHE_LINE_SIZE	32

#define KVM_AP_NONE    		0
#define KVM_AP_RDONLY  		1
#define KVM_AP_RDWRITE 		2

#define KVM_MEM_EXEC    	0
#define KVM_MEM_NOEXEC  	1

#define L1_TYPE_MASK	  	0x3
#define L1_TYPE_FAULT	 	0x0
#define L1_TYPE_COARSE		0x1
#define L1_TYPE_SECTION		0x2

#define CP15_CR_BIT_XP		23

/*
 * map_info.cache_bits encoding:
 *
 *  8      6   5 4   3   2     0
 * +---------+-----+---+---+-----+
 * |   TEX   | 0 0 | C | B | 0 0 |
 * +---------+-----+---+---+-----+
 */

#define CACHE_BITS_MASK		(0x1cc)
#define CACHE_BITS_B_SHIFT	2
#define CACHE_BITS_B_MASK	(0x1 << CACHE_ITS_B_SHIFT)
#define CACHE_BITS_C_SHIFT	3
#define CACHE_BITS_C_MASK	(0x1 << CACHE_ITS_C_SHIFT)
#define CACHE_BITS_TEX_SHIFT	6
#define CACHE_BITS_TEX_MASK	(0x7 << CACHE_BITS_TEX_SHIFT)


/*
 * Detailed info about a guest page mapping
 */
struct map_info {
	u32 cache_bits;
	u8 domain_number;
	u8 ap;
#if __LINUX_ARM_ARCH__ >= 6
	u8 apx;
	u8 xn;
#endif
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
extern struct list_head kvm_shadow_pgtable_list;


kvm_shadow_pgtable* kvm_alloc_l1_shadow(struct kvm_vcpu *vcpu,
					gva_t guest_ttbr);
int   kvm_init_l1_shadow(struct kvm_vcpu *vcpu, kvm_shadow_pgtable *shadow);
void  kvm_free_l1_shadow(struct kvm_vcpu *vcpu, kvm_shadow_pgtable *shadow);
int __map_gva_to_pfn(struct kvm_vcpu *vcpu, u32 *pgd, gva_t gva, pfn_t pfn,
		     u8 domain, u8 ap, u8 apx, u8 xn, u32 cache_bits);
int   map_gva_to_pfn(struct kvm_vcpu *vcpu, u32 *pgd, gva_t gva, pfn_t pfn,
		     u8 domain, u8 priv_ap, u8 user_ap, u8 exec);
int   unmap_gva(u32 *pgd, gva_t gva);
int   unmap_gva_section(struct kvm_vcpu *vcpu, u32 *pgd, gva_t gva);
int   kvm_update_special_region_ap(struct kvm_vcpu *vcpu, u32 *pgd, u8 domain);
int   kvm_restore_low_vector_domain(struct kvm_vcpu *vcpu, u32 *pgd);
int   kvm_switch_host_vectors(struct kvm_vcpu *vcpu, int high);
int   kvm_update_shadow_ap(struct kvm_vcpu *vcpu, kvm_shadow_pgtable *shadow);
void  dump_l1_pgtable(struct kvm_vcpu *vcpu);
void  kvm_tlb_flush_guest_all(kvm_shadow_pgtable *shadow);

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
 * return 1 if CP15 control register has extended page tables enabled
 * (VMSAv6, subpages disabled) and 0 otherwise (VMSAv6, subpages enabled,
 * VMSAv4/v5)
 */
static inline int kvm_mmu_xp(struct kvm_vcpu *vcpu)
{
	return (vcpu->arch.cp15.c1_CR & (1 << CP15_CR_BIT_XP)) ? 1 : 0;
}

/*
 * Decode access permissions.
 *
 * @vcpu:    The virtual cpu struct pointer
 * @ap:      The access permission bits
 * @uaccess: Return user access permissions even if VCPU is in privileged mode
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
static inline u8 calc_aps(u8 priv, u8 user, u8 *apx)
{
	if (priv == KVM_AP_NONE && user == KVM_AP_NONE) {
		*apx = 0;
		return 0x0;
	} else if (user == KVM_AP_NONE) {
		*apx = (priv == KVM_AP_RDONLY)? 1 : 0;
		return 0x1;
	} else if (user == KVM_AP_RDONLY) {
		*apx = (priv == KVM_AP_RDONLY)? 1 : 0;
		return 0x2;
	} else if (user == KVM_AP_RDWRITE) {
		*apx = 0;
		return 0x3;
	} else {
		BUG();
		*apx = 0;
		return 0; /* GCC is braindead */
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

/* TODO: Make these work on all platforms */
static inline void kvm_dcache_clean(void)
{
	unsigned long zero = 0;
	asm volatile ("mcr p15, 0, %[zero], c7, c10, 0\n": :
		      [zero] "r" (zero));
}

static inline void kvm_cache_clean_invalidate_all(void)
{
	unsigned long zero = 0;
	asm volatile ("mcr p15, 0, %[zero], c7, c14, 0\n"
		      "mcr p15, 0, %[zero], c7, c5, 0\n": :
		      [zero] "r" (zero));
}

extern void v6_inv_cache_addr(unsigned long addr, unsigned long size);
static inline void kvm_cache_inv_user(void __user *ptr, unsigned long n)
{
	unsigned long va = (unsigned long)ptr;
	if (!access_ok(VERIFY_READ, ptr, n))
		return;

	v6_inv_cache_addr(va, n);
}

void kvm_coherent_to_guest(gva_t gva, void *hva, unsigned long n);
void kvm_coherent_from_guest(gva_t gva, void *hva, unsigned long n);
void v6_clean_inv_dcache_sw(unsigned long addr);
void v6_clean_dcache_sw(unsigned long addr);

#endif /* __ARM_KVM_ARM_MMU_H__ */
