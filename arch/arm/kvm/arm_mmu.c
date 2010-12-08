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
#include <linux/kvm_types.h>
#include <linux/kvm_host.h>
#include <linux/highmem.h>
#include <linux/mman.h>
#include <linux/module.h>
#include <linux/kvm_host.h>
#include <linux/slab.h>
#include <asm/page.h>
#include <asm/pgtable.h>
#include <asm/mman.h>
#include <asm/mmu_context.h>
#include <asm/domain.h>
#include <asm/uaccess.h>
#include <asm/tlbflush.h>

/********* Trace and debug definitions ***********/
bool trace_gva_to_gfn = false;
/*************************************************/

#include <asm/kvm_arm.h>
#include <asm/kvm_asm.h>
#include <asm/kvm_mmu.h>

#include "trace.h"

extern u8 guest_debug;

/******************************************************************************
 * ARM common defines
 *****************************************************************************/
#define SECTION_BASE_MASK     	0xfff00000
#define SECTION_BASE_INDEX_MASK	0x000fffff
#define SUP_BASE_INDEX_MASK     0x00ffffff
#define PAGES_PER_SECTION     	(SECTION_SIZE >> PAGE_SHIFT)

#define VA_L1_IDX_MASK		(0xfff << 20)
#define VA_L1_IDX_SHIFT		18 /* 2 extra bits for word index */
#define VA_L2_IDX_MASK		(0xff << 12)
#define VA_L2_IDX_SHIFT		10 /* 2 extra bits for word index */

#define L1_TABLE_ENTRIES	(1 << 12)
#define L1_TABLE_SIZE		(L1_TABLE_ENTRIES << 2)
#define L1_TABLE_PAGES		(L1_TABLE_SIZE / PAGE_SIZE)
#define L1_TABLE_ORDER		2
#define L1_COARSE_SHIFT		10
#define L1_COARSE_MASK		(~0x3ff)
#define L1_DOMAIN_SHIFT		5
#define L1_DOMAIN_MASK		(0xf << L1_DOMAIN_SHIFT)
#define L1_SECTION_AP_SHIFT	10
#define L1_SECTION_AP_MASK	(0x3 << L1_SECTION_AP_SHIFT)

#define L2_TABLE_SHIFT		10
#define L2_TABLE_ENTRIES	256
#define L2_TABLE_SIZE		(1UL << L2_TABLE_SHIFT)
#define L2_TABLES_PER_PAGE	L2_TABLE_SIZE / PAGE_SIZE

#define L2_TYPE_MASK		0x3
#define L2_TYPE_FAULT		0x0
#define L2_TYPE_LARGE		0x1

#define L2_LARGE_BASE_SHIFT	16
#define L2_LARGE_BASE_MASK	(0xffff << L2_LARGE_BASE_SHIFT)
#define VA_LARGE_INDEX_MASK	(0xffff)


/******************************************************************************
 * ARM v6 (VMSAv6) defines
 *****************************************************************************/
#if __LINUX_ARM_ARCH__ >= 6

#define L1_SECTION_TYPE_SHIFT		18
#define L1_SECTION_TYPE_MASK		(1 << L1_SECTION_TYPE_SHIFT)
#define L1_SECTION_TYPE_SECTION		(0 << L1_SECTION_TYPE_SHIFT)
#define L1_SECTION_TYPE_SUPERSECTION	(1 << L1_SECTION_TYPE_SHIFT)

#define L1_SUP_BASE_SHIFT		24
#define L1_SUP_BASE_MASK		(0xff << L1_SUP_BASE_SHIFT)
#define L1_SUP_BASE_LOW_SHIFT		20
#define L1_SUP_BASE_LOW_MASK		(0xf << L1_SUP_BASE_LOW_SHIFT)
#define L1_SUP_BASE_HIGH_SHIFT		5
#define L1_SUP_BASE_HIGH_MASK		(0xf << L1_SUP_BASE_HIGH_SHIFT)


#define L2_EXT_SMALL_BASE_SHIFT		12
#define L2_EXT_SMALL_BASE_MASK		(0xfffff << L2_EXT_SMALL_BASE_SHIFT)
#define VA_EXT_SMALL_INDEX_MASK		(0xfff)

#define L2_TYPE_EXT_SMALL		0x3
#define L2_XP_TYPE_EXT_SMALL		0x2

#endif /* __LINUX_ARM_ARCH__ >= 6 */


/******************************************************************************
 * ARM v5 defines (VMSAv6, subpages enabled)
 *****************************************************************************/
#define L2_TYPE_SMALL		0x2
#define L2_TYPE_TINY		0x3

#define L2_SMALL_BASE_SHIFT	12
#define L2_SMALL_BASE_MASK	(0xfffff << L2_SMALL_BASE_SHIFT)
#define VA_SMALL_INDEX_MASK	(0xfff)

#define L2_TINY_BASE_SHIFT	10
#define L2_TINY_BASE_MASK	(0x3fffff << L2_TINY_BASE_SHIFT)
#define VA_TINY_INDEX_MASK	(0x3ff)



/**
 * Returns a gfn known not to be visible to the guest
 */
static gfn_t invisible_gfn(struct kvm *kvm)
{
	gfn_t gfn = 0xffffff;
	int i;

	for (i = 0; i < KVM_MEMORY_SLOTS; i++) {
		if (!kvm_is_visible_gfn(kvm, gfn))
			break;

		gfn = kvm->memslots[i].base_gfn - 1;
	}
	BUG_ON(kvm_is_visible_gfn(kvm, gfn));

	return gfn;
}


/*
 * This function will map in the guest page table page determined by the
 * base end the index, copy out the value and unmap the page agin.
 *
 * The function will acquire current->mm_mmap_sem() and realease it again.
 */
static inline int get_guest_pgtable_entry(struct kvm_vcpu *vcpu, u32 *entry,
				   gpa_t table_entry)
{
	int ret;
	gfn_t gfn;
	unsigned int offset;
	unsigned long addr;

	/*
	 * Cache coherency is guaranteed here since we are reading on the same
	 * conditions as the TLB would be reading on actual hardware (given we
	 * invalidate our side of the cache) so the guest must take care of any
	 * coherency issues such as draining the write buffer etc. before this
	 * walk will ever take place.
	 */
	gfn = table_entry >> PAGE_SHIFT;
	offset = offset_in_page(table_entry);
	addr = gfn_to_hva(vcpu->kvm, gfn);

	if (kvm_is_error_hva(addr))
		return -EFAULT;

	/* kvm_cache_inv_user((void __user *)addr + offset, sizeof(u32)); */

	ret = copy_from_user(entry, (void __user *)addr + offset, sizeof(u32));
	if (ret)
		return -EFAULT;
	kvm_arm_count_event(EVENT_READ_GUEST_ENTRY);
	return 0;
}

#if __LINUX_ARM_ARCH__ >= 6
static int trans_coarse_entry_xp(struct kvm_vcpu *vcpu, gva_t gva,
				 u32 desc, gfn_t *gfn, u8 domain_type,
				 u8 uaccess, struct map_info *map_info)
{
	gpa_t page_base;
	u32 page_index;
	int ret = 0;

	switch (desc & L2_TYPE_MASK) {
	case L2_TYPE_FAULT:
		/*printk(KERN_DEBUG "     guest page fault at 0x%08x on GVA: 0x%08x\n",
				vcpu->arch.regs[15],
				(unsigned int)gva);*/
		*gfn = invisible_gfn(vcpu->kvm);
		return FSR_TRANS_PAGE;
	case L2_TYPE_LARGE:
		KVMARM_NOT_IMPLEMENTED();
		page_base = desc & L2_LARGE_BASE_MASK;
		page_index = gva & VA_LARGE_INDEX_MASK;
		break;
	case (L2_XP_TYPE_EXT_SMALL):		/* XN-bit not set */
	case (L2_XP_TYPE_EXT_SMALL | 0x1):	/* XN-bit set */
		map_info->ap = (desc >> 4) & 0x3;
		map_info->apx = (desc >> 9) & 0x1;
		map_info->xn = desc & 0x1;
		map_info->cache_bits = desc & CACHE_BITS_MASK;

		if (domain_type == DOMAIN_CLIENT) {
			u8 ap = map_info->ap;
			if (kvm_decode_ap(vcpu, ap, uaccess) == KVM_AP_NONE)
				ret = FSR_PERM_PAGE;
		}
		page_base = desc & L2_EXT_SMALL_BASE_MASK;
		page_index = gva & VA_EXT_SMALL_INDEX_MASK;
		break;
	default:
		kvm_err(-EINVAL, "unknown L2 descriptor type");
		return -EINVAL;

	}

	*gfn = (page_base | page_index) >> PAGE_SHIFT;
	return ret;
}
#endif

static int trans_coarse_entry(struct kvm_vcpu *vcpu, gva_t gva,
			      u32 desc, gfn_t *gfn, u8 domain_type,
			      u8 uaccess, struct map_info *map_info)
{
	gpa_t page_base;
	u32 page_index;
	int ret = 0;

	BUG(); /* This code has bit-rotted somewhat */

	switch (desc & L2_TYPE_MASK) {
	case L2_TYPE_FAULT:
		/*printk(KERN_DEBUG "     guest page fault at 0x%08x on GVA: 0x%08x\n",
				vcpu->arch.regs[15],
				(unsigned int)gva);*/
		*gfn = invisible_gfn(vcpu->kvm);
		return FSR_TRANS_PAGE;
	case L2_TYPE_LARGE:
		KVMARM_NOT_IMPLEMENTED();
		page_base = desc & L2_LARGE_BASE_MASK;
		page_index = gva & VA_LARGE_INDEX_MASK;
		break;
	case L2_TYPE_SMALL: {
		u8 ap = (desc >> 4) & 0xff;
		if (kvm_mmu_xp(vcpu))
			return -EINVAL;

		map_info->ap = ap;
#if __LINUX_ARM_ARCH__ >=6
		/*
		 * We currently do not support different subpage permissions
		 * as we always use extended page table format on ARMv6.
		 */
		if ((ap & 0x3) != ((ap >> 2) & 0x3) ||
		    (ap & 0x3) != ((ap >> 4) & 0x3) ||
		    (ap & 0x3) != ((ap >> 6) & 0x3)) {
			printk(KERN_INFO "Guest uses different subpage permissions.\n");
			return -EINVAL;
		}
#endif
		map_info->cache_bits = (desc & 0xc);

		if (domain_type == DOMAIN_CLIENT) {
			u8 subpage = (gva >> 10) & 0x3;
			u8 ap = (desc >> (4 + (subpage*2))) & 0x3;
			if (kvm_decode_ap(vcpu, ap, uaccess) == KVM_AP_NONE)
				ret = FSR_PERM_PAGE;
		}
		page_base = desc & L2_SMALL_BASE_MASK;
		page_index = gva & VA_SMALL_INDEX_MASK;
		break;
	}
#if __LINUX_ARM_ARCH__ >= 6
	case L2_TYPE_EXT_SMALL: {
		u8 ap = (desc >> 4) & 0x3;
		map_info->ap = ap | (ap<<2) | (ap<<4) | (ap<<6);
		map_info->cache_bits = desc & CACHE_BITS_MASK;

		if (domain_type == DOMAIN_CLIENT) {
			if (kvm_decode_ap(vcpu, ap, uaccess) == KVM_AP_NONE)
				ret = FSR_PERM_PAGE;
		}
		page_base = desc & L2_EXT_SMALL_BASE_MASK;
		page_index = gva & VA_EXT_SMALL_INDEX_MASK;
		break;
	}
#endif
	default:
		BUG();
	}

	*gfn = (page_base | page_index) >> PAGE_SHIFT;
	return ret;
}

#if __LINUX_ARM_ARCH__ >= 6
static inline int is_supersection(u32 l1_entry)
{
	return !((l1_entry & L1_SECTION_TYPE_MASK) == L1_SECTION_TYPE_SECTION);
}
#endif

/*
 * Checks if the domain setting on an ARM level 1 descriptor allows the
 * VCPU access for that data range.
 */
static int l1_domain_access(struct kvm_vcpu *vcpu, u32 l1_entry,
			    struct map_info *map_info)
{
	u8 domain;
	u8 type;


#if __LINUX_ARM_ARCH__ >= 6
	if (is_supersection(l1_entry))
		domain = 0;
	else
#endif
		domain = (l1_entry & L1_DOMAIN_MASK) >> L1_DOMAIN_SHIFT;

	map_info->domain_number = domain;

	type = vcpu->arch.cp15.c3_DACR & domain_val(domain, DOMAIN_MANAGER);
	return type >> (2*domain);
}

/*
 * Guest virtual to guest physical.
 *
 * This function will actually walk the guest page tables to do
 * the translation and thus copy in user space data.
 *
 * For some reason it's necessary to clean the entire D-cache before
 * we start reading guest page table entries on ARMv6 - even though the
 * guest kernel should flush the write. This may be related to assumptions
 * about disabled MMU behavior or memory type attributes on the guest page
 * tables but attempts to accomodate that have not been successful.
 *
 * vcpu:    The virtual cpu
 * gva:     The guest virtual address
 * gfn:     Either a visible guest frame number on or invisible_gfn.
 *	    Value should be checked with kvm_is_visible_gfn().
 * uaccess: The access permissions should be checked in user mode
 *
 * returns: >= 0 on success:
 *		 FSR_XXXX_XXX if there was some kind of fault when
 *		 traversing guest page tables and finally
 * 	    < 0: negative error code
 */
int gva_to_gfn(struct kvm_vcpu *vcpu, gva_t gva, gfn_t *gfn, u8 uaccess,
	       struct map_info *map_info)
{
	gpa_t l1_base, l2_base;
	u32 l1_index, l2_index;
	u32 l1_entry, l2_entry;
	gpa_t gpa;
	u8 ap, domain_type;
	int err;
	struct map_info tmp_map_info;
	int ret = 0;

	if (!map_info)
		map_info = &tmp_map_info;


	/* GVA == GPA when guest MMU is disabled */
	if (!kvm_mmu_enabled(vcpu)) {
		map_info->domain_number = 0;
		map_info->ap = 0xff;
#if __LINUX_ARM_ARCH__ >= 6
		map_info->apx = 0;
		map_info->xn = 0;
		map_info->cache_bits = 0x08;
#endif
		*gfn = (gva >> PAGE_SHIFT);
		return 0;
	}

	/* Get the L1 descriptor */
	l1_base = kvm_guest_ttbr(&vcpu->arch, gva);
	l1_index = (gva & VA_L1_IDX_MASK) >> VA_L1_IDX_SHIFT;
	err = get_guest_pgtable_entry(vcpu, &l1_entry, l1_base | l1_index);
	if (err < 0)
		return err;

	if (trace_gva_to_gfn)
		kvm_msg("l1_entry: %08x", l1_entry);

	switch (l1_entry & L1_TYPE_MASK) {
	case (L1_TYPE_FAULT): {
		/*printk(KERN_DEBUG "     guest section fault at 0x%08x on GVA: 0x%08x\n",
				vcpu->arch.regs[15],
				(unsigned int)gva);*/
		*gfn = invisible_gfn(vcpu->kvm);
		return FSR_TRANS_SEC;
	}
	case (L1_TYPE_COARSE): {
		domain_type =  l1_domain_access(vcpu, l1_entry, map_info);
		if (domain_type == DOMAIN_NOACCESS) {
			ret = FSR_DOMAIN_PAG;
		}

		l2_base = l1_entry & L1_COARSE_MASK;
		l2_index = (gva & VA_L2_IDX_MASK) >> VA_L2_IDX_SHIFT;
		err = get_guest_pgtable_entry(vcpu, &l2_entry,
					      l2_base | l2_index);
		if (err < 0)
			return err;

		if (trace_gva_to_gfn)
			kvm_msg("l2_entry: %08x", l2_entry);

#if __LINUX_ARM_ARCH__ >= 6
		if (kvm_mmu_xp(vcpu))
			err = trans_coarse_entry_xp(vcpu, gva, l2_entry, gfn,
						    domain_type, uaccess,
						    map_info);
		else
#endif
			err = trans_coarse_entry(vcpu, gva, l2_entry, gfn,
						 domain_type, uaccess,
						 map_info);

		if (err < 0)
			return err;

		if (ret == 0 && err > 0) {
			if (trace_gva_to_gfn) {
				kvm_msg("l1 entry for 0x%08x: 0x%08x", gva, l1_entry);
				kvm_msg("l2 entry for 0x%08x: 0x%08x", gva, l2_entry);
				kvm_msg("err: %d", err);
				kvm_msg("xp: %u", kvm_mmu_xp(vcpu));
			}
			return err; /* Maybe AP denied on the 2nd level */
		} else
			return ret;
	}
	case (L1_TYPE_SECTION): {
		/* Get guest mapping info */
		ap = (l1_entry & L1_SECTION_AP_MASK) >> L1_SECTION_AP_SHIFT;
		map_info->ap = ap | (ap<<2) | (ap<<4) | (ap<<6);
#if __LINUX_ARM_ARCH__ >= 6
		if (kvm_mmu_xp(vcpu)) {
			map_info->apx = (l1_entry >> 14) & 1;
			map_info->xn = (l1_entry >> 4) & 1;
		}
#endif
		map_info->cache_bits = l1_entry & 0xc; /* C and B bits */
		map_info->cache_bits |= (l1_entry >> 6) & 0x1c0; /* TEX bits */

		/* Get and check guest domain mapping info */
		domain_type = l1_domain_access(vcpu, l1_entry, map_info);
		if (domain_type == DOMAIN_NOACCESS) {
			ret = FSR_DOMAIN_SEC;
		} else if (domain_type == DOMAIN_CLIENT) {
			if (kvm_decode_ap(vcpu, ap, uaccess) == KVM_AP_NONE) {
				ret = FSR_PERM_SEC;
			}
		}

		/* Finally, calculate address */
#if __LINUX_ARM_ARCH__ >= 6
		if (kvm_mmu_xp(vcpu) && is_supersection(l1_entry)) {
			/* TODO: Base address [39:36] on non arm1136? */
			if (((l1_entry >> L1_SUP_BASE_LOW_SHIFT) & 0xf) ||
			    ((l1_entry >> L1_SUP_BASE_HIGH_SHIFT) & 0xf)) {
				kvm_err(-EINVAL, "larger physical address space "
					"than 32 bits not supported");
				return -EINVAL;
			}

			gpa = (l1_entry & L1_SUP_BASE_MASK) |
				(gva & SUP_BASE_INDEX_MASK);
			*gfn = (gpa >> PAGE_SHIFT);
		} else {
			gpa = (l1_entry & SECTION_BASE_MASK) |
				(gva & SECTION_BASE_INDEX_MASK);
			*gfn = (gpa >> PAGE_SHIFT);
		}
#else
			gpa = (l1_entry & SECTION_BASE_MASK) |
				(gva & SECTION_BASE_INDEX_MASK);
			*gfn = (gpa >> PAGE_SHIFT);
#endif
		return ret;
	}
	default:
		BUG();
	}

	BUG();
	return 0;
}

#if 0
void print_guest_mapping(struct kvm_vcpu *vcpu, gva_t gva)
{
	gpa_t l1_base, l2_base;
	u32 l1_index, l2_index;
	u32 l1_entry, l2_entry;
	int err;

	if (!kvm_mmu_enabled(vcpu)) {
		return;
	}

	/* Get the L1 descriptor */
	l1_base = kvm_guest_ttbr(&vcpu->arch, gva);
	l1_index = (gva & VA_L1_IDX_MASK) >> VA_L1_IDX_SHIFT;
	err = get_guest_pgtable_entry(vcpu, &l1_entry, l1_base | l1_index);
	BUG_ON(err < 0);
	printk(KERN_DEBUG "                       guest l1_pte: 0x%08x\n", l1_entry);

	switch (l1_entry & L1_TYPE_MASK) {
	case (L1_TYPE_FAULT): {
		printk(KERN_DEBUG "            guest section fault on GVA: 0x%08x\n",
				(unsigned int)gva);
		return;
	}
	case (L1_TYPE_COARSE): {
		l2_base = l1_entry & L1_COARSE_MASK;
		l2_index = (gva & VA_L2_IDX_MASK) >> VA_L2_IDX_SHIFT;
		err = get_guest_pgtable_entry(vcpu, &l2_entry,
					      l2_base | l2_index);
		BUG_ON(err < 0);

		printk(KERN_DEBUG "                       guest l2_pte: 0x%08x\n", l2_entry);
		return;
	}
	case (L1_TYPE_SECTION): {
		printk(KERN_DEBUG "               guest section mapping\n");
		return;
	}
	default:
		BUG();
	}

	BUG();
	return;
}
#endif

/*
 * Guest virtual to host virtual.
 *
 * vcpu: The virtual cpu
 * gva:  The guest virtual address
 *
 * returns: Valid host virtual address on success, or bad_hva() on
 *	    error. Return value should be checked with kvm_is_error_hva().
 */
hva_t gva_to_hva(struct kvm_vcpu *vcpu, gva_t gva, u8 uaccess)
{
	gfn_t gfn;
	hva_t hva;
	int ret;

	ret = gva_to_gfn(vcpu, gva, &gfn, uaccess, NULL);
	if ((ret < 0) || (!kvm_is_visible_gfn(vcpu->kvm, gfn)))
		return PAGE_OFFSET; //bad_hva

	hva = gfn_to_hva(vcpu->kvm, gfn);
	if (kvm_is_error_hva(hva))
		return hva;

	return hva + (gva & ((1<<PAGE_SHIFT) - 1));
}

/*
 * ============================================================================
 * MMU management functions:
 *
 *
 *
 *
 * ============================================================================
 */

/**
 * Allocate a new blank shadow page table where all addresses are unmapped.
 * You must call another function actually initialize this table, if necessary.
 */
kvm_shadow_pgtable* kvm_alloc_l1_shadow(struct kvm_vcpu *vcpu,
					gva_t guest_ttbr)
{
	kvm_shadow_pgtable *shadow;

	if (!(shadow = kmalloc(sizeof(kvm_shadow_pgtable), GFP_KERNEL)))
		return ERR_PTR(-ENOMEM);

	/* Allocate contigous aligned pages */
	shadow->pgd = (u32*)__get_free_pages(GFP_KERNEL, L1_TABLE_ORDER);
	if (!shadow->pgd)
		return ERR_PTR(-ENOMEM);

	memset(shadow->pgd, 0, L1_TABLE_SIZE);
	shadow->pa = page_to_phys(virt_to_page(shadow->pgd));
#ifdef CONFIG_CPU_HAS_ASID
	shadow->id = __new_asid();
#endif
	shadow->guest_ttbr = guest_ttbr;

	list_add_tail(&shadow->list, &vcpu->arch.shadow_pgtable_list);

	return shadow;
}

static bool mapping_is_guest_writable(struct kvm_vcpu *vcpu,
				      u8 domain,
				      u32 pte)
{
	u8 ap;
	u32 dacr = (vcpu->arch.cp15.c3_DACR & 0x3fffffff)
		   | domain_val(DOMAIN_KVM, DOMAIN_CLIENT);

	/* TODO: Enforce shadow page table version */
	BUG_ON(domain > 15);
	switch (dacr >> (domain*2)) {
	case DOMAIN_MANAGER:
		return true;
	case DOMAIN_CLIENT:
		ap = (pte >> 4) & 0x3;
		if (kvm_decode_ap(vcpu, ap, 0) == KVM_AP_RDWRITE)
			return true;
		else
			return false;
	case DOMAIN_NOACCESS:
		return false;
	}

	return false; /* GCC is braindead */
}

/**
 * Release a page pointed to by a shadow page table
 *
 * @vcpu:   The vcpu pointer for the VCPU on which the shadow page table runs
 * @domain: The domain to which the coarse mapping belongs
 * @pte:    The level-2 shadow page table entry
 */
static void inline release_l2_shadow_entry(struct kvm_vcpu *vcpu, u8 domain,
					   u32 pte, gva_t gva)
{
	pfn_t pfn;

	switch (pte & L2_TYPE_MASK) {
	case L2_TYPE_FAULT:
		return;
#if __LINUX_ARM_ARCH__ >= 6
	case (L2_XP_TYPE_EXT_SMALL):		/* XN-bit not set */
	case (L2_XP_TYPE_EXT_SMALL | 0x1):	/* XN-bit set */
#else
	case (L2_TYPE_SMALL):
#endif
		pfn = __phys_to_pfn(pte & L2_SMALL_BASE_MASK);

		if (!pfn_valid(pfn))
			kvm_msg("invalid pfn: %u (pte: 0x%08x) (gva: 0x%08x)",
					pfn, pte, gva);

		/*
		 * TODO: Do we really want to release KVM vector and shared
		 * page here?
		 */
		if (mapping_is_guest_writable(vcpu, domain, pte))
			kvm_release_pfn_dirty(pfn);
		else
			kvm_release_pfn_clean(pfn);

		break;
	default:
		/* Large pages not supported in shadow page tables */
		kvm_msg("shadow page table entry type not supported");
		BUG();
	}

}

/**
 * Free a level-2 shadow page table.
 *
 * Decrease the use count of a 1-kilobyte L2 shadow table. The max value of this
 * count is four (meaning 4 L2 tables per 4KB Linux page frame. If the value
 * hits zero, the linux page that contains that descriptor is also freed.
 *
 * The guest pages allocated by user space and mapped in this shadow
 * page table are also released throught the architecture generic KVM interface.
 *
 * @vcpu:     The vcpu pointer for the VCPU on which the shadow page table runs
 * @l1_pte:   The first-level page table entry pointing to the level-2 table
 */
static void free_l2_shadow(struct kvm_vcpu *vcpu, u32 l1_pte, u32 gva_base)
{
	struct page *page;
	unsigned int i;
	u8 domain;
	u32 *pte;
	pfn_t pfn;

	pfn = __phys_to_pfn(l1_pte & L1_COARSE_MASK);
	if (!pfn_valid(pfn)) {
		kvm_msg("invalid pfn: %u (l1_pte: 0x%08x)",
				pfn, l1_pte);
	}
	page = pfn_to_page(l1_pte >> PAGE_SHIFT);
	pte = (u32 *)((u32)page_address(page) | (l1_pte & 0xc00));

	for (i = 0; i < L2_TABLE_ENTRIES; i++) {
		domain = (l1_pte & L1_DOMAIN_MASK) >> L1_DOMAIN_SHIFT;
		release_l2_shadow_entry(vcpu, domain, *pte, gva_base | (i << 12));

		/*
		 * There is not need to clean the pte entries in cache here
		 * as the level-1 entries have been cleaned and cleared.
		 */

		pte++;
	}

	put_page(page);
}

/*
 * Iterate through each L1 descriptor and free all of the child tables pointed
 * to by those L1 descriptors.
 */
static void __free_l1_shadow_children(struct kvm_vcpu *vcpu, u32 *pgd)
{
	u32 l1_pte = pgd[0];
	unsigned int i;

	for(i = 0; i < L1_TABLE_ENTRIES; i++, l1_pte = pgd[i]) {
		if ((l1_pte & L1_TYPE_MASK) == L1_TYPE_FAULT)
			continue;
		if ((l1_pte & L1_TYPE_MASK) != L1_TYPE_COARSE)
			BUG();

		free_l2_shadow(vcpu, l1_pte, i << 20);

		pgd[i] = 0;
		clean_pmd_entry((pmd_t *)(pgd + i));
	}
}

/*
 * XXX FIXME: There should be separate l2_unused_pt pointer per L1 root table. In the
 * case of multiple processes, each L1 root will have its own l2_unused_pt
 * pointer. If this is not done, some degree of fragementation may occur if this
 * global l2_unused_pt pointer is reset prematurely.
 */
static void free_l1_shadow_children(struct kvm_vcpu *vcpu, u32 *pgd)
{
	if (pgd == NULL) {
		kvm_msg("Weird pgd == NULL!");
		return;
	}
	__free_l1_shadow_children(vcpu, pgd);
	vcpu->arch.l2_unused_pt = NULL;
}

/*
 * This will do two things: not only will it free the L1 root table itself, but
 * it will also free all the child L2 tables pointed to by that table.
 *
 * Will also remove the shadow page table from the list of available shadow
 * page tables on the vcpu struct.
 */
void kvm_free_l1_shadow(struct kvm_vcpu *vcpu, kvm_shadow_pgtable *shadow)
{
	free_l1_shadow_children(vcpu, shadow->pgd);
	free_pages((ulong) shadow->pgd, L1_TABLE_ORDER);
	list_del(&shadow->list);
	kfree(shadow);
}

/*
 * Initialize a 16KB contiguously aligned L1 root page table by mapping in the
 * interrupt vectors and shared page.
 *
 * If the table has existing mappings to L2 shadow tables, those L2 tables
 * will be freed.
 */
static u8 init_l1_map = 0;
int kvm_init_l1_shadow(struct kvm_vcpu *vcpu, kvm_shadow_pgtable *shadow)
{
	int ret = 0;
	gva_t exception_base;

	kvm_arm_count_event(EVENT_FLUSH_SHADOW);
	//kvm_msg("flushing shadow page table at: 0x%08x!", vcpu->arch.regs[15]);

	if (shadow->pgd == NULL) {
		kvm_msg("Weird pgd == NULL!");
		return -EINVAL;
	}

	free_l1_shadow_children(vcpu, shadow->pgd);

	get_page(virt_to_page(vcpu->arch.shared_page_alloc));
	ret = map_gva_to_pfn(vcpu,
			     shadow->pgd,
			     (gva_t) vcpu->arch.shared_page,
			     page_to_pfn(virt_to_page(vcpu->arch.shared_page_alloc)),
			     DOMAIN_KVM,
			     KVM_AP_RDWRITE,
			     KVM_AP_NONE,
			     KVM_MEM_EXEC);
	if (ret < 0)
		return ret;

	if (vcpu->arch.host_vectors_high)
		exception_base = EXCEPTION_VECTOR_HIGH;
	else
		exception_base = EXCEPTION_VECTOR_LOW;

	init_l1_map = 1;
	get_page(virt_to_page(vcpu->arch.guest_vectors));
	ret = map_gva_to_pfn(vcpu,
			     shadow->pgd,
			     exception_base,
			     page_to_pfn(virt_to_page(vcpu->arch.guest_vectors)),
			     DOMAIN_KVM,
			     KVM_AP_RDWRITE,
			     KVM_AP_NONE,
			     KVM_MEM_EXEC);
	init_l1_map = 0;

	kvm_tlb_flush_guest_all(shadow);

	if (ret < 0) {
		printk(KERN_ERR "Failed to map guest vectorss\n");
		return ret;
	}

	return 0;
}

/*
 * This will unmap the original host vector address and map
 * in the new host vector address in the shadow page tables.
 */
int kvm_switch_host_vectors(struct kvm_vcpu *vcpu, int high)
{
	int ret;
	gva_t exception_base;
	char *ch = "high";
	char *cl = "low";

	if (high == vcpu->arch.host_vectors_high) {
		kvm_msg("vector switch not necessary");
		return 0;
	}

	kvm_msg("host switched to using %s vectors", high ? ch : cl);

	if (high) {
		kvm_trace_activity(70, "Switch host vectors to high vectors");
		ret = unmap_gva_section(vcpu,
					vcpu->arch.shadow_pgtable->pgd,
					EXCEPTION_VECTOR_LOW);
		if (ret)
			return ret;
		//kvm_restore_low_vector_domain(vcpu, vcpu->arch.shadow_pgtable);
		exception_base = EXCEPTION_VECTOR_HIGH;
		vcpu->arch.host_vectors_high = 1;
	} else {
		kvm_trace_activity(71, "Switch host vectors to low vectors");
		ret = unmap_gva(vcpu->arch.shadow_pgtable,
				EXCEPTION_VECTOR_HIGH);
		if (ret)
			return ret;
		exception_base = EXCEPTION_VECTOR_LOW;
		vcpu->arch.host_vectors_high = 0;
	}

	get_page(virt_to_page(vcpu->arch.guest_vectors));
	ret = map_gva_to_pfn(vcpu,
			     vcpu->arch.shadow_pgtable->pgd,
			     exception_base,
			     page_to_pfn(virt_to_page(vcpu->arch.guest_vectors)),
			     DOMAIN_KVM,
			     KVM_AP_RDWRITE,
			     KVM_AP_NONE,
			     KVM_MEM_EXEC);
	kvm_tlb_flush_guest_all(vcpu->arch.shadow_pgtable);
	return ret;
}

/*
 * Allocate an L2 descriptor table by storing multiple 1-KB descriptors into a
 * single 4KB linux page frame at a time.
 */
static inline u32 *alloc_l2_shadow(struct kvm_vcpu *vcpu)
{
	u32 * l2_base = vcpu->arch.l2_unused_pt;
	struct page *page;

	if (!l2_base) {
		l2_base = (u32*)__get_free_pages(GFP_KERNEL, 0);
		if (!l2_base) {
			printk(KERN_ERR "Can't allocate L2 shadow page table.\n");
			return ERR_PTR(-ENOMEM);
		}
		page = virt_to_page(l2_base);
		memset(l2_base, 0, PAGE_SIZE);
	} else {
		get_page(virt_to_page(l2_base));
	}

	vcpu->arch.l2_unused_pt = l2_base + (L2_TABLE_SIZE / sizeof(u32));

	if ((u32)vcpu->arch.l2_unused_pt % PAGE_SIZE == 0)
		vcpu->arch.l2_unused_pt = NULL;

	return l2_base;
}

/**
 * Find the access permissions equivalent to the passed domain
 *
 * @vcpu:	The VCPU struct
 * @domain:	The domain to convert to equivalent AP
 * @ap:		The access permissions used if domain is client
 */
static inline u8 dom_to_ap(struct kvm_vcpu *vcpu, u8 domain, u8 ap, u8 *apx)
{
	if (VCPU_DOMAIN_VAL(vcpu, domain) == DOMAIN_NOACCESS) {
		*apx = 0;
		return 0;
	} else if (VCPU_DOMAIN_VAL(vcpu, domain) == DOMAIN_MANAGER) {
		*apx = 0;
		return 0xff;
	} else {
		return ap;
	}
}

int get_l2_base(u32 l1_entry, u32 **l2_base)
{
	pfn_t l2_pfn;
	struct page *page;

	l2_pfn = l1_entry >> PAGE_SHIFT;

	if (!pfn_valid(l2_pfn)) {
		printk(KERN_ERR "Shadow page table contains invalid mappings.\n");
		printk(KERN_ERR "  L1 descriptor: %08x\n", l1_entry);
		return -EFAULT;
	}
	page = pfn_to_page(l2_pfn);
	BUG_ON(page == NULL);
	*l2_base = (u32 *)((u32)page_address(page) + (l1_entry & 0xc00));
	return 0;
}

static inline u32 sanitize_cache_bits(u32 cache_bits)
{
	cache_bits = cache_bits & CACHE_BITS_MASK;

	if (cache_bits != 0x8 &&	/* Normal, write through, no w-allocate */
	    cache_bits != 0xc &&	/* Normal, write back, w-allocate */
	    cache_bits != 0x40 &&	/* Normal, Non-cacheable */
	    cache_bits != 0x4c &&	/* Normal, Write back, w-allocate */
	    !(cache_bits & 0x100)) { 	/* Normal, specific outer/innter */

		/* Device and reserved memory becomes normal non-cachable */
		return 0x40;
	}

	return cache_bits;
}

/**
 * see map_gva_to_pfn(...) below
 */
int __map_gva_to_pfn(struct kvm_vcpu *vcpu, u32 *pgd, gva_t gva, pfn_t pfn,
		     u8 domain, u8 ap, u8 apx, u8 xn, u32 cache_bits)
{
	u32 l1_index;
	u32 *l1_pte, *l2_base, *l2_pte;
	u8 nG = 1;
	int ret;

	l1_index = gva >> 20;

	kvm_arm_count_event(EVENT_MAP_GVA_TO_GFN);

	/*
	 * The shared page should be kept in the TLB across guest/host and even
	 * on return to user space as no-one else should use the page.
	 *
	 * ARMv6:
	 * All kernel mappings are global, since we flush this address range
	 * on world switches.
	 */
	//if ((gva & PAGE_MASK) == SHARED_PAGE_BASE || gva > TASK_SIZE)
	if ((gva & PAGE_MASK) == SHARED_PAGE_BASE)
		nG = 0;

	if (domain == DOMAIN_KVM)
		goto skip_domain_check;

	if (l1_index == (SHARED_PAGE_BASE >> 20)) {
		/* This L1 mapping coincides with that of the shared page */
		//XXX Track updates to L1 domain by protecting guest pg. tables

		/*  For now we simply flush page tables instead of using this
		vcpu->arch.shared_page_guest_domain = domain;
		vcpu->arch.shared_page_shadow_ap[(gva >> 12) & 0xff] = ap;
		*/

		ap = dom_to_ap(vcpu, domain, ap, &apx);
		domain = DOMAIN_KVM;
	} else if (l1_index == (VCPU_HOST_EXCP_BASE(vcpu) >> 20)) {
		/* This L1 mapping coincides with that of the vector page */
		//XXX Track updates to L1 domain by protecting guest pg. tables

		/*  For now we simply flush page tables instead of using this
		vcpu->arch.vector_page_guest_domain = domain;
		vcpu->arch.vector_page_shadow_ap[(gva >> 12) & 0xff] = ap;
		*/
		ap = dom_to_ap(vcpu, domain, ap, &apx);
		domain = DOMAIN_KVM;
	}

skip_domain_check:
	domain = domain & 0xf;
	l1_pte = pgd + l1_index;
	switch ((*l1_pte) & L1_TYPE_MASK) {
	case (L1_TYPE_FAULT):
		l2_base = alloc_l2_shadow(vcpu);
		if (IS_ERR(l2_base))
			return PTR_ERR(l2_base);

		/*
		 * Set the First-level mapping to map into the allocated
		 * second-level table above.
		 */
		*l1_pte = page_to_phys(virt_to_page(l2_base));
		*l1_pte |= ((u32)l2_base) & ~PAGE_MASK;
		*l1_pte = (*l1_pte & L1_COARSE_MASK) | L1_TYPE_COARSE;
		*l1_pte |= (domain << L1_DOMAIN_SHIFT);
		flush_pmd_entry((pmd_t *)l1_pte);
		break;
	case (L1_TYPE_COARSE):
		/* Update the domain of the L1 mapping */
		*l1_pte &= ~L1_DOMAIN_MASK;
		*l1_pte |= (domain << L1_DOMAIN_SHIFT);

		flush_pmd_entry((pmd_t *)l1_pte);

		ret = get_l2_base(*l1_pte, &l2_base);
		if (ret)
			return ret;

		break;
	default:
		printk(KERN_ERR "map_gva_to_pfn: This function supports "
					  "only coarse mappings.\n");
		printk(KERN_ERR "  L1 descriptor: %08x\n", *l1_pte);
		return -EFAULT;
	}

	l2_pte = l2_base + ((gva >> 12) & 0xff);
#if __LINUX_ARM_ARCH__ >= 6

	/* VMSAv6 and higher */
	*l2_pte = (pfn << PAGE_SHIFT) | L2_XP_TYPE_EXT_SMALL;
	*l2_pte |= (xn & 0x1);
	*l2_pte |= sanitize_cache_bits(cache_bits);
	*l2_pte &= ~(0x00000e30); //Necessary bit clear?
	*l2_pte |= (ap & 0x3) << 4;
	*l2_pte |= (apx & 0x1) << 9;
	*l2_pte |= nG << 11;

	/*if ((*l2_pte & CACHE_BITS_MASK) != 0xc)
		kvm_msg("l2 pte with different cache bits: %08x (%x)",
				*l2_pte, *l2_pte & CACHE_BITS_MASK);
				*/
#else
	/* VMSAv6 backwards-compatible mode */
	*l2_pte = (pfn << PAGE_SHIFT) | L2_TYPE_SMALL;
	*l2_pte |= 0xc; // Normal memory, cache write back
	*l2_pte &= ~(0x00000ff0);
	*l2_pte |= ap << 4;
#endif
	clean_dcache_area(l2_pte, sizeof(u32));
	kvm_tlb_flush_guest_all(vcpu->arch.shadow_pgtable);

	return 0;
}

/**
 * Maps virtual->physical memory in pgd
 *
 * This function will map the page containing the virtual address
 * to the corresponding page number passed in pfn. Overwrites any existing
 * mappings in that place.
 *
 * @vcpu:    The virtual CPU
 * @pgd:     Pointer to page directory of translation table create mapping
 * @gva:     The virtual address
 * @pfn:     The physical frame number to map to
 * @domain   The access domain for the entry
 * @priv_ap: Privileged access permissions (See KVM_AP_XXXXX)
 * @user_ap: User mode access permissions (See KVM_AP_XXXXX)
 * @xn:      1 => execute never, 0 => execute
 */
int map_gva_to_pfn(struct kvm_vcpu *vcpu, u32 *pgd, gva_t gva, pfn_t pfn,
		   u8 domain, u8 priv_ap, u8 user_ap, u8 exec)
{
	u8 ap, apx, calc_ap, i;
	u32 cache_bits;

	/*
	 * Check validity of access permissions
	 */
	if (priv_ap == KVM_AP_NONE && user_ap != KVM_AP_NONE)
		return -EINVAL;
	if (kvm_mmu_xp(vcpu)) {
		if (priv_ap == KVM_AP_RDONLY && user_ap == KVM_AP_RDWRITE)
			return -EINVAL;
	} else {
		if (priv_ap == KVM_AP_RDONLY)
			return -EINVAL;
	}

	/*
	 * Calculate access permissions to VMSAvX format
	 */
	calc_ap = calc_aps(priv_ap, user_ap, &apx);
	ap = 0;
	for (i = 0; i < 4; i++)
		ap |= calc_ap << (i*2); // Same AP on all subpages

	/*
	 * Set cache bits for shared page and interrupt vector page
	 * to normal, write-black, no write-allocate
	 */
	cache_bits = 0xc;


	/*
	 * Call lower level function
	 */
	return __map_gva_to_pfn(vcpu, pgd, gva, pfn,
				domain, ap, apx, exec, cache_bits);
}

int unmap_gva_section(struct kvm_vcpu *vcpu, u32 *pgd, gva_t gva)
{
	u32 *l1_pte;

	l1_pte = pgd + (gva >> 20);
	switch ((*l1_pte) & L1_TYPE_MASK) {
	case (L1_TYPE_FAULT):
		/* Already unmapped */
		return 0;
	case (L1_TYPE_COARSE):
		kvm_msg("unmap_gva_section, gva: 0x%08x", gva);
		free_l2_shadow(vcpu, *l1_pte, gva);
		*l1_pte = 0x0;
		clean_pmd_entry((pmd_t *)l1_pte);
		kvm_tlb_flush_guest_all(vcpu->arch.shadow_pgtable);
		return 0;
	default:
		printk(KERN_ERR "unmap_gva_section: This function supports "
					  "only coarse mappings.\n");
		printk(KERN_ERR "  L1 descriptor: %08x\n", *l1_pte);
		return -EFAULT;
	}
}

int unmap_gva(struct kvm_shadow_pgtable *shadow, gva_t gva)
{
	u32 *l1_pte, *l2_base, *l2_pte;
	int ret;
	u32 *pgd = shadow->pgd;

	l1_pte = pgd + (gva >> 20);
	switch ((*l1_pte) & L1_TYPE_MASK) {
	case (L1_TYPE_FAULT):
		/* Already unmapped */
		return 0;
	case (L1_TYPE_COARSE):
		/* TODO: Free something here? */
		ret = get_l2_base(*l1_pte, &l2_base);
		if (ret)
			return ret;

		l2_pte = l2_base + ((gva >> 12) & 0xff);
		*l2_pte = 0x0;
		clean_dcache_area(l2_pte, sizeof(u32));
		kvm_tlb_flush_guest_all(shadow);
		return 0;
	default:
		printk(KERN_ERR "unmap_gva: This function supports "
					  "only coarse mappings.\n");
		printk(KERN_ERR "  L1 descriptor: %08x\n", *l1_pte);
		return -EFAULT;
	}
}


#if 0
/*
 * Will update the L2 AP bits to equal those of the guest mapping with respect
 * to the possible domain values.
 *
 *	    @vcpu: The virtual CPU pointer
 *	     @pgd: The shadow page table
 * @violating gva: The virtual address that caused us not to be able
 *		   to use the guest native domain in the first place.
 *	     @aps: The 256-element array of APs as they would appear in the
 *		   shadow page tables (ie. after dom_to_ap() )
 *       @convert: Whether to convert APs to correspond to a different guest
 *		   domain than in execution DACR
 *	     @dom: The domain number used in the guest mapping
 */
static inline int update_l2_aps(struct kvm_vcpu *vcpu, u32 *pgd,
				gva_t violating_gva, u8 *aps,
				u8 convert, u8 dom)
{
	int i, ret;
	u32 *l2_pte;
	u32 *l2_base;
	u32 l1_index, l1_entry;
	u32 exception_base;
	gva_t gva;
	u8 ap;

	l1_index = violating_gva >> 20;
	l1_entry = *(pgd + l1_index);
	BUG_ON((l1_entry & L1_TYPE_MASK) != L1_TYPE_COARSE);

	ret = get_l2_base(l1_entry, &l2_base);
	if (ret)
		return ret;

	exception_base = VCPU_HOST_EXCP_BASE(vcpu);
	for (i = 0; i < (1<<8); i++) {
		/* If we need to convert APs then the section is still mapping
		 * a special page and we don't want to change the AP of a
		 * special page. */
		gva = (l1_index << 20) | (i << PAGE_SHIFT);
		if (convert && (gva == (violating_gva & PAGE_MASK)))
			continue;

		l2_pte = l2_base + i;
		*l2_pte &= ~(0xff << 4);
		if (convert)
			ap = dom_to_ap(vcpu, dom, aps[i]);
		else
			ap = aps[i];

		*l2_pte |= (u32)ap << 4;
	}

	return 0;
}

/*
 * This function should be called when the guest changes domains on the
 * page tables or when the DAC register is updated.
 *
 * It will change the AP bits on the L2 descriptors in the shadow page
 * table, which belong to the same L1 section (and thereby domain setting)
 * as either of the special pages to match the intended behavior by the guest.
 */
int kvm_update_special_region_ap(struct kvm_vcpu *vcpu, u32 *pgd, u8 domain)
{
	gva_t exception_base;
	int ret = 0;
	u8 shared_dom = vcpu->arch.shared_page_guest_domain;
	u8 vector_dom = vcpu->arch.vector_page_guest_domain;


	if (domain == shared_dom) {
		ret = update_l2_aps(vcpu, pgd, SHARED_PAGE_BASE,
				    vcpu->arch.shared_page_shadow_ap,
				    1, domain);
	}

	exception_base = VCPU_HOST_EXCP_BASE(vcpu);
	if (domain == vector_dom &&
	    (exception_base >> 20) != (SHARED_PAGE_BASE >> 20)) {
		ret = update_l2_aps(vcpu, pgd, exception_base,
				    vcpu->arch.vector_page_shadow_ap,
				    1, domain);

	}

	return ret;
}

/*
 * This function should be called when the host switches to high vectors.
 * It will find the low vector L1 entry and restore the guest domain, and
 * restore the L2 ap's pointed to by that L1 descriptor.
 *
 * It should be called before mapping in the new host vector page as we
 * need some of the stored information regarding the original mappings
 * tied to the vector location on the vcpu->arch struct.
 */
int kvm_restore_low_vector_domain(struct kvm_vcpu *vcpu, u32 *pgd)
{
	u32 *l1_pte;
	int ret = 0;
	gva_t exception_base = EXCEPTION_VECTOR_LOW;
	BUG_ON(vcpu->arch.host_vectors_high);

	/* Update the domain to use the native guest domain */
	l1_pte = (pgd + (exception_base >> 20));
	*l1_pte &= ~L1_DOMAIN_MASK;
	*l1_pte |= ((vcpu->arch.vector_page_guest_domain & 0xf)
			<< L1_DOMAIN_SHIFT);

	/* Update all the L2 APs, which were maybe synthesized before */
	ret = update_l2_aps(vcpu, pgd, exception_base,
			    vcpu->arch.vector_page_shadow_ap, 0, -1);

	return ret;
}
#endif

static int update_shadow_l2_ap(struct kvm_vcpu *vcpu, u32 *l1_pte, u32 *l2_base)
{
	struct map_info map_info;
	gva_t gva;
	gfn_t gfn;
	int ret;
	u8 ap;
	u32 *l2_pte = l2_base;

	while (l2_pte < (l2_base + 256)) {
		if ((*l2_pte & L2_TYPE_MASK) == L2_TYPE_FAULT)
			goto next_l2_entry;

		gva = (((u32)l1_pte & (L1_TABLE_SIZE-1)) << 18) +
			(((u32)l2_pte & (L2_TABLE_SIZE-1)) << 10);

		if (gva == VCPU_HOST_EXCP_BASE(vcpu) ||
		    gva == SHARED_PAGE_BASE)
			goto next_l2_entry;

		ret = gva_to_gfn(vcpu, gva, &gfn, 0, &map_info);
		if (ret < 0)
			return ret;

		ap = convert_guest_to_shadow_ap(vcpu, map_info.ap);

		if ((gva >> 20) == (SHARED_PAGE_BASE >> 20) ||
		    (gva >> 20) == (VCPU_HOST_EXCP_BASE(vcpu) >> 20)) {
			ap = dom_to_ap(vcpu, map_info.domain_number,
				       ap, &map_info.apx);
		}

		*l2_pte &= ~PTE_EXT_AP_MASK;
		*l2_pte |= (ap & 0x3) << 4;
		clean_dcache_area(l2_pte, sizeof(u32));

next_l2_entry:
		l2_pte++;
	}

	return 0;
}

/*
 * Update the access permission bits on the shadow page table to match
 * the intented protection from guest page tables on for example a switch
 * between privileged and user mode.
 *
 * @vcpu:   The virtual CPU pointer.
 * @shadow: The shadow page table pointer to update APs on.
 */
int kvm_update_shadow_ap(struct kvm_vcpu *vcpu, kvm_shadow_pgtable *shadow)
{
	u32 *l1_pte;
	u32 *l2_pte;
	int ret;

	kvm_coherent_from_guest_all();
	for (l1_pte = shadow->pgd; l1_pte < shadow->pgd + 4096; l1_pte++) {
		if ((*l1_pte & L1_TYPE_MASK) != L1_TYPE_FAULT) {
			ret = get_l2_base(*l1_pte, &l2_pte);
			if (ret)
				return ret;

			ret = update_shadow_l2_ap(vcpu, l1_pte, l2_pte);
			if (ret)
				return ret;
		}
	}

	kvm_cache_clean_invalidate_all();
	kvm_tlb_flush_guest_all(shadow);
	return 0;
}


/* =========================================================================
 * Interrupt emulation functions
 * =========================================================================
 */
void kvm_generate_mmu_fault(struct kvm_vcpu *vcpu, gva_t fault_addr,
			    u32 source, u8 domain)
{
	/*
	 * The vcpu->arch.guest_exception is set upon exit from the guest
	 * as this is the only way to know if the fault was due to an instruction
	 * prefetch or a data access.
	 */
	if (vcpu->arch.guest_exception == ARM_EXCEPTION_PREF_ABORT) {
		/*printk(KERN_DEBUG "    Generating EXCEPTION_PREFETCH at 0x%08x: "
				                  "0x%08x (0x%x)\n\n",
				(unsigned int)vcpu->arch.regs[15],
				(unsigned int)fault_addr,
				(unsigned int)source);*/
		vcpu->arch.cp15.c6_IFAR = fault_addr;
		vcpu->arch.cp15.c5_IFSR = 0;
		vcpu->arch.cp15.c5_IFSR |= source & FSR_TYPE_MASK;
		vcpu->arch.cp15.c5_IFSR |= (domain & 0xf) << 4;
		vcpu->arch.exception_pending |= EXCEPTION_PREFETCH;
	} else {
		/*printk(KERN_DEBUG "    Generating EXCEPTION_DATA at 0x%08x: "
				                  "0x%08x (0x%x)\n\n",
				(unsigned int)vcpu->arch.regs[15],
				(unsigned int)fault_addr,
				(unsigned int)source);*/
		vcpu->arch.cp15.c6_FAR = fault_addr;
		vcpu->arch.cp15.c5_DFSR = 0;
		vcpu->arch.cp15.c5_DFSR |= source & FSR_TYPE_MASK;
		vcpu->arch.cp15.c5_DFSR |= (domain & 0xf) << 4;
		vcpu->arch.cp15.c5_DFSR = source;

		vcpu->arch.exception_pending |= EXCEPTION_DATA;
	}
}

/* =========================================================================
 * TLB and Cache Management
 * =========================================================================
 */
void kvm_tlb_flush_guest_all(kvm_shadow_pgtable *shadow)
{
	local_flush_tlb_asid(current->mm, shadow->id & 255);
}



/*
 * Poor man's log2 algorithm - assumes input is 2^n
 */
static unsigned int cheap_log2(unsigned int input)
{
	unsigned int log = 0;
	unsigned int round = 0;

	if (input == 1)
		round = 1; // Round up

	while (input > 1) {
		if ((input & 1) == 1)
			round = 1;
		input = input >> 1;
		log++;
	}
	return log + round;
}

static void get_cache_set_way_params(unsigned int *L,
				     unsigned int *A,
				     unsigned int *S)
{
	unsigned long cache_type;
	unsigned long dcache;
	unsigned int len, M, size, assoc;
	unsigned int linelen, associativity, nsets;

	asm __volatile__ ("mrc p15, 0, %[ct], c0, c0, 1": [ct] "=r" (cache_type));
	dcache = (cache_type >> 12) & 0xfff;

	len = dcache & 3;
	M = (dcache >> 2) & 1;
	assoc = (dcache >> 3) & 7;
	size = (dcache >> 6) & 0xf;

	if (assoc == 0 && M == 1)
		return; /* No cache */

	linelen = 1 << (len + 3);
	associativity = (2 + M) << (assoc - 1);
	nsets = 1 << (size + 6 - assoc - len);

	*L = cheap_log2(linelen);
	*A = cheap_log2(associativity);
	*S = cheap_log2(nsets);
}

/*
 * Clean or invalidate the cache.
 *
 * @addr: The virtual address to clean/invalidate
 */
static void v6_cleaninv_sw(unsigned long addr, bool clean, bool invalidate)
{
	unsigned int L, A, S;
	unsigned int set_way, max_set, way, max_way;
	BUG_ON(!clean && !invalidate);

	L = 0; A = 0; S = 0; /* GCC is braindead */
	get_cache_set_way_params(&L, &A, &S);

	max_set = (1 << S) - 1;
	set_way = ((addr >> L) & max_set) << L;

	max_way = (1 << A) - 1;
	for (way = 0; way <= max_way; way++) {
		set_way &= (1 << (32 - A)) - 1;
		set_way |= way << (32 - A);

		if (clean && invalidate) {
			asm volatile ("mcr p15, 0, %[set_way], c7, c14, 2": :
					[set_way] "r" (set_way));
		} else if (clean) {
			/* Just clean */
			asm volatile ("mcr p15, 0, %[set_way], c7, c10, 2": :
					[set_way] "r" (set_way));
		} else {
			/* Just invalidate */
			asm volatile ("mcr p15, 0, %[set_way], c7, c6, 2": :
					[set_way] "r" (set_way));
		}
	}


}

void v6_clean_dcache_sw(unsigned long addr)
{
	v6_cleaninv_sw(addr, true, false);
}

void v6_clean_inv_dcache_sw(unsigned long addr)
{
	v6_cleaninv_sw(addr, true, true);
}

/*
 * Ensure cache coherency when accessing guest data
 * from host using a user space pointer
 *
 * @gva:  The guest virtual address to read
 * @hva:  The user space pointer passed to copy_from_user
 */
void kvm_coherent_from_guest(gva_t gva, void *hva, unsigned long n)
{
	unsigned long offset = 0;
	gva = (gva & (~(D_CACHE_LINE_SIZE - 1)));

	while (offset < n) {
		v6_clean_dcache_sw(gva + offset);
		offset += D_CACHE_LINE_SIZE;
	}
	kvm_cache_inv_user((void __user *)hva, n);
}

/*
 * Ensure cache coherency when writing guest date
 * from host using a user space pointer
 *
 * @gva:  The guest virtual address to read
 * @hva:  The user space pointer passed to copy_from_user
 */
void kvm_coherent_to_guest(gva_t gva, void *hva, unsigned long n)
{
	int offset = 0;
	gva = (gva & (~(D_CACHE_LINE_SIZE - 1)));

	clean_dcache_area(hva, n);
	while (offset < n) {
		v6_clean_inv_dcache_sw(gva + offset);
		offset += D_CACHE_LINE_SIZE;
	}
}
