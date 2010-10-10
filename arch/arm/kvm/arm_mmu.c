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
#include <asm/domain.h>
#include <asm/uaccess.h>
#include <asm/kvm_arm.h>
#include <asm/kvm_asm.h>
#include <asm/kvm_mmu.h>

extern u8 guest_debug;
extern u8 page_debug;
/*
 * ARM v5 defines
 * (should probably be more complex and conditional #ifdefs
 * when more architecures are supported).
 */
#define VA_L1_IDX_MASK	      (0xfff << 20)
#define VA_L1_IDX_SHIFT	      18 /* 2 extra bits for word index */
#define VA_L2_IDX_MASK	      (0xff << 12)
#define VA_L2_IDX_SHIFT	      10 /* 2 extra bits for word index */

#define L1_TABLE_ENTRIES      (1 << 12)
#define L1_TABLE_SIZE         (L1_TABLE_ENTRIES << 2)
#define L1_TABLE_PAGES        (L1_TABLE_SIZE / PAGE_SIZE)
#define L1_TABLE_ORDER        2
#define L1_COARSE_MASK        (~0x2ff)
#define L1_DOMAIN_SHIFT	      5
#define L1_DOMAIN_MASK        (0xf << L1_DOMAIN_SHIFT)
#define L1_SECTION_AP_SHIFT   10
#define L1_SECTION_AP_MASK    (0x3 << L1_SECTION_AP_SHIFT)

#define L2_TABLE_ENTRIES      ENTRIES_PER_PAGE   (PAGE_SIZE / sizeof(hva_t))
#define L2_TABLE_SHIFT        10
#define L2_TABLE_SIZE         (1UL << L2_TABLE_SHIFT)
#define L2_TABLES_PER_PAGE    L2_TABLE_SIZE / PAGE_SIZE
#define L2_TYPE_MASK          0x3
#define L2_TYPE_FAULT         0x0
#define L2_TYPE_LARGE         0x1
#define L2_TYPE_SMALL         0x2
#define L2_TYPE_TINY          0x3
#define L2_TYPE_EXT_SMALL     0x3

#define L2_LARGE_BASE_SHIFT   16
#define L2_LARGE_BASE_MASK    (0xffff << L2_LARGE_BASE_SHIFT) 
#define VA_LARGE_INDEX_MASK   (0xffff)

#define L2_SMALL_BASE_SHIFT   12
#define L2_SMALL_BASE_MASK    (0xfffff << L2_SMALL_BASE_SHIFT) 
#define VA_SMALL_INDEX_MASK   (0xfff)

#define L2_TINY_BASE_SHIFT    10
#define L2_TINY_BASE_MASK     (0x3fffff << L2_TINY_BASE_SHIFT) 
#define VA_TINY_INDEX_MASK    (0x3ff)


#define TRANSLATION_BASE_MASK 0xffffc000
#define SECTION_BASE_MASK     0xfff00000
#define BASE_INDEX_MASK       0x000fffff
#define PAGES_PER_SECTION     (SECTION_SIZE >> PAGE_SHIFT)


static gfn_t __invisible_gfn(struct kvm *kvm)
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
static int get_guest_pgtable_entry(struct kvm_vcpu *vcpu, u32 *entry,
				   gpa_t table_entry)
{
	hva_t host_base, host_entry;
	u32 table_page_offset;
	struct page *entry_page;
	u32 *mapping;
	int ret;

	host_base = gfn_to_hva(vcpu->kvm, table_entry >> PAGE_SHIFT);
	if (kvm_is_error_hva(host_base)) {
		printk(KERN_ERR "Guest page table address invalid: %08x\n",
				(unsigned int)table_entry);
		return -EFAULT;
	}
	table_page_offset = table_entry % PAGE_SIZE;
	host_entry = host_base + table_page_offset;

	down_write(&current->mm->mmap_sem);
	ret = get_user_pages(current, current->mm, host_entry, 1, 0, 0,
			               &entry_page, NULL);
	if (ret != 1) {
		up_write(&current->mm->mmap_sem);
		BUG();
	}

	mapping = (u32 *)kmap(entry_page);
	*entry = *(mapping + (table_page_offset / sizeof(u32)));
	kunmap(entry_page);
	put_page(entry_page);

	up_write(&current->mm->mmap_sem);

	return 0;
}

static int translate_coarse_descriptor(struct kvm_vcpu *vcpu, gva_t gva,
					 u32 desc, gfn_t *gfn, u8 domain_type,
					 u8 uaccess, struct map_info *map_info)
{
	gpa_t page_base;
	u32 page_index;
	int ret = 0;

	switch (desc & L2_TYPE_MASK) {
	case L2_TYPE_FAULT: {
		/*printk(KERN_DEBUG "     guest page fault at 0x%08x on GVA: 0x%08x\n",
				vcpu->arch.regs[15],
				(unsigned int)gva);*/
		*gfn = __invisible_gfn(vcpu->kvm);
		return FSR_TRANS_PAGE;
	}
	case L2_TYPE_LARGE: {
		KVMARM_NOT_IMPLEMENTED();
		page_base = desc & L2_LARGE_BASE_MASK;
		page_index = gva & VA_LARGE_INDEX_MASK;
		break;
	}
	case L2_TYPE_SMALL: {
		map_info->ap = (desc >> 4) & 0xff;

		if (domain_type == DOMAIN_CLIENT) {
			u8 subpage = (gva >> 10) & 0x3;
			u8 ap = (desc >> (4 + (subpage*2))) & 0x3;
			if (kvm_decode_ap(vcpu, ap, uaccess) == KVM_AP_NONE) {
				ret = FSR_PERM_PAGE;
			}
		}
		page_base = desc & L2_SMALL_BASE_MASK;
		page_index = gva & VA_SMALL_INDEX_MASK;
		break;
	}
#ifdef CONFIG_CPU_32v5
	case L2_TYPE_TINY: {
		KVMARM_NOT_IMPLEMENTED();
		page_base = desc & L2_TINY_BASE_MASK;
		page_index = gva & VA_TINY_INDEX_MASK;
		break;
	}
#endif
#if defined CONFIG_CPU_32v6 || defined CONFIG_CPU_32v7
	case L2_TYPE_EXT_SMALL: {
		KVMARM_NOT_IMPLEMENTED();
		break;
	}
#endif
	default:
		BUG();
	}
	
	*gfn = (page_base | page_index) >> PAGE_SHIFT;
	return ret;
}

/*
 * Checks if the domain setting on an ARM level 1 descriptor allows the
 * VCPU access for that data range.
 */
static int l1_domain_access(struct kvm_vcpu *vcpu, u32 l1_entry,
			    struct map_info *map_info)
{
	u8 domain;
	u8 type;

	domain = (l1_entry & L1_DOMAIN_MASK) >> L1_DOMAIN_SHIFT;
	map_info->domain_number = domain;

	type = vcpu->arch.cp15.c3_DACR & domain_val(domain, DOMAIN_MANAGER);
	return type >> (2*domain);
}

/*
 * Guest virtual to guest physical.
 *
 * This function will actually walk the guest page tables to do
 * the translation and thus map in user space memory in the kernel
 * address space to do the walk.
 *
 * vcpu:    The virtual cpu
 * gva:     The guest virtual address
 * gfn:     Either a visible guest frame number on or invisible_gfn.
 *          Value should be checked with kvm_is_visible_gfn().
 * uaccess: The access permissions should be checked in user mode
 *
 * returns: >= 0 on success:
 *               FSR_XXXX_XXX if there was some kind of fault when
 * 	         traversing guest page tables and finally
 * 	    < 0: negative error code
 */
int gva_to_gfn(struct kvm_vcpu *vcpu, gva_t gva, gfn_t *gfn, u8 uaccess,
	       struct map_info *map_info)
{
	gpa_t l1_base, l2_base;
	u32 l1_index, l2_index;
	u32 l1_entry, l2_entry;
	gpa_t gpa;
	u8 domain_type;
	int err;
	struct map_info tmp_map_info;
	int ret = 0;

	if (!map_info)
		map_info = &tmp_map_info;

	/* GVA == GPA when guest MMU is disabled */
	if (!kvm_mmu_enabled(vcpu)) {
		map_info->domain_number = 0;
		map_info->ap = 0xff;
		*gfn = (gva >> PAGE_SHIFT);
		return 0;
	}

	/* Get the L1 descriptor */
	l1_base = vcpu->arch.cp15.c2_TTBR & TRANSLATION_BASE_MASK;
	l1_index = (gva & VA_L1_IDX_MASK) >> VA_L1_IDX_SHIFT; 
	err = get_guest_pgtable_entry(vcpu, &l1_entry, l1_base | l1_index);
	if (err < 0)
		return err;

	switch (l1_entry & L1_TYPE_MASK) {
	case (L1_TYPE_FAULT): {
		/*printk(KERN_DEBUG "     guest section fault at 0x%08x on GVA: 0x%08x\n",
				vcpu->arch.regs[15],
				(unsigned int)gva);*/
		*gfn = __invisible_gfn(vcpu->kvm);
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

		err = translate_coarse_descriptor(vcpu, gva, l2_entry, gfn,
						  domain_type, uaccess, map_info);
		if (err < 0)
			return err;

		if (ret == 0 && err > 0)
			return err; /* Maybe AP denied on the 2nd level */
		else
			return ret;
	}
	case (L1_TYPE_SECTION): {
		//u8 ap = (l1_entry >> L1_SECTION_AP_SHIFT) & 0x3);
		u8 ap = (l1_entry & L1_SECTION_AP_MASK) >> L1_SECTION_AP_SHIFT;
		domain_type = l1_domain_access(vcpu, l1_entry, map_info);
		map_info->ap = ap | (ap<<2) | (ap<<4) | (ap<<6);
		if (domain_type == DOMAIN_NOACCESS) {
			ret = FSR_DOMAIN_SEC;
		} else if (domain_type == DOMAIN_CLIENT) {
			if (kvm_decode_ap(vcpu, ap, uaccess) == KVM_AP_NONE) {
				ret = FSR_PERM_SEC;
			}
		}

		gpa = (l1_entry & SECTION_BASE_MASK) | (gva & BASE_INDEX_MASK);
		*gfn = (gpa >> PAGE_SHIFT);
		return ret;
	}
	default:
		BUG();
	}

	BUG();
	return 0;
}

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
	l1_base = vcpu->arch.cp15.c2_TTBR & TRANSLATION_BASE_MASK;
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

/*
 * Guest virtual to host virtual.
 *
 * vcpu: The virtual cpu
 * gva:  The guest virtual address
 *
 * returns: Valid host virtual address on success, or bad_hva() on
 *          error. Return value should be checked with kvm_is_error_hva().
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

/*
 * Allocate a new blank shadow page table where all addresses are unmapped.
 * You must call another function actually initialize this table, if necessary.
 */
u32* kvm_alloc_l1_shadow(struct kvm_vcpu *vcpu)
{
	u32 *pgd;
	
	/* Allocate contigous aligned pages */
	pgd = (u32*)__get_free_pages(GFP_KERNEL, 2);
	if (!pgd) {
		printk(KERN_ERR "Could not allocate first-level shadow page table.\n");
		return ERR_PTR(-ENOMEM);
	}
	memset(pgd, 0, L1_TABLE_SIZE);

	return pgd;
}

/*
 * Decrease the use count of a 1-kilobyte L2 shadow table. The max value of this
 * count is four (meaning 4 L2 tables per 4KB Linux page frame. If the value
 * hits zero, the linux page that contains that descriptor is also freed.
 */
static void free_l2_shadow(u32 l2_pfn) {
	struct page *page = pfn_to_page(l2_pfn);

	BUG_ON(page_private(page) == 0);

	if(--page_private(page) == 0)
		free_page((ulong) page_address(page));
}

/*
 * Iterate through each L1 descriptor and free all of the child tables pointed
 * to by those L1 descriptors.
 */
static void __free_l1_shadow_children(u32 *root) {
	u32 l1_pte = root[0];
	int i;

	for(i = 0; i < L1_TABLE_ENTRIES; i++, l1_pte = root[i]) {
		if ((l1_pte & L1_TYPE_MASK) == L1_TYPE_FAULT)
			continue;
		if ((l1_pte & L1_TYPE_MASK) != L1_TYPE_COARSE)
			BUG();
		
		free_l2_shadow(l1_pte >> PAGE_SHIFT);

		root[i] = 0;
	}
}

/*
 * XXX FIXME: There should be separate l2_unused_pt pointer per L1 root table. In the
 * case of multiple processes, each L1 root will have its own l2_unused_pt
 * pointer. If this is not done, some degree of fragementation may occur if this
 * global l2_unused_pt pointer is reset prematurely. 
 */
static void free_l1_shadow_children(struct kvm_vcpu *vcpu, u32 *shadow) {
	BUG_ON(shadow == NULL);
	__free_l1_shadow_children(shadow);
	vcpu->arch.l2_unused_pt = NULL;
}

/*
 * This will do two things: not only will it free the L1 root table itself, but
 * it will also free all the child L2 tables pointed to by that table.
 */
void kvm_free_l1_shadow(struct kvm_vcpu *vcpu, u32 **pgdp)
{
	u32 *shadow = NULL;

	BUG_ON(pgdp == NULL);
	BUG_ON(*pgdp == NULL);

	shadow = *pgdp;
	free_l1_shadow_children(vcpu, shadow);
	free_pages((ulong) shadow, L1_TABLE_ORDER);
	*pgdp = NULL;
}

/*
 * Initialize a 16KB contiguously aligned L1 root page table by mapping in the
 * interrupt vectors and shared page.
 * 
 * If the table has existing mappings to L2 shadow tables, those L2 tables
 * will be freed.
 */
static u8 init_l1_map = 0;
int kvm_init_l1_shadow(struct kvm_vcpu * vcpu, u32 * pgd)
{
	int ret = 0;
	gva_t exception_base;

	if (page_debug) {
		printk(KERN_DEBUG "Flushing shadow page table at: 0x%08x!\n",
			vcpu->arch.regs[15]);
	}

	BUG_ON(pgd == NULL);

	free_l1_shadow_children(vcpu, pgd);

	ret = map_gva_to_pfn(vcpu,
			     pgd,
			     (gva_t) vcpu->arch.shared_page,
			     page_to_pfn(virt_to_page(vcpu->arch.shared_page_alloc)),
			     KVM_SPECIAL_DOMAIN,
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
	ret = map_gva_to_pfn(vcpu,
			     pgd,
                             exception_base,
                             page_to_pfn(virt_to_page(vcpu->arch.guest_vectors)),
			     KVM_SPECIAL_DOMAIN,
			     KVM_AP_RDWRITE,
			     KVM_AP_NONE,
			     KVM_MEM_EXEC);
	init_l1_map = 0;


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
	
	if (high == vcpu->arch.host_vectors_high)
		return 0;

	printk(KERN_DEBUG "       switched to %s vectors\n", high ? ch : cl);

	if (high) {
		ret = unmap_gva_section(vcpu->arch.shadow_pgtable, EXCEPTION_VECTOR_LOW);
		if (ret)
			return ret;
		//kvm_restore_low_vector_domain(vcpu, vcpu->arch.shadow_pgtable);
		exception_base = EXCEPTION_VECTOR_HIGH;
		vcpu->arch.host_vectors_high = 1;
	} else {
		ret = unmap_gva(vcpu->arch.shadow_pgtable, EXCEPTION_VECTOR_HIGH);
		if (ret)
			return ret;
		exception_base = EXCEPTION_VECTOR_LOW;
		vcpu->arch.host_vectors_high = 0;
	}

	ret = map_gva_to_pfn(vcpu,
			     vcpu->arch.shadow_pgtable,
                             exception_base,
                             page_to_pfn(virt_to_page(vcpu->arch.guest_vectors)),
			     KVM_SPECIAL_DOMAIN,
			     KVM_AP_RDWRITE,
			     KVM_AP_NONE,
			     KVM_MEM_EXEC);
	return ret;
}

/*
 * Allocate an L2 descriptor table by storing multiple 1-KB descriptors into a
 * single 4KB linux page frame at a time.
 */
static inline u32 * alloc_l2_shadow(struct kvm_vcpu *vcpu)
{
	u32 * l2_base = vcpu->arch.l2_unused_pt;

	if (!l2_base) {
		l2_base = (u32*)__get_free_pages(GFP_KERNEL, 0);
		if (!l2_base) {
			printk(KERN_ERR "Can't allocate L2 shadow page table.\n");
			return ERR_PTR(-ENOMEM);
		}
		memset(l2_base, 0, PAGE_SIZE);
		page_private(virt_to_page(l2_base)) = 0;
	}

	vcpu->arch.l2_unused_pt = l2_base + (L2_TABLE_SIZE / sizeof(u32));

	if ((u32)vcpu->arch.l2_unused_pt % PAGE_SIZE == 0)
		vcpu->arch.l2_unused_pt = NULL;

	page_private(virt_to_page(l2_base))++;

	return l2_base;
}

static inline u8 convert_domain_to_ap(struct kvm_vcpu *vcpu, u8 domain, u8 ap)
{
	if (VCPU_DOMAIN_VAL(vcpu, domain) == DOMAIN_NOACCESS)
		return 0;
	else if (VCPU_DOMAIN_VAL(vcpu, domain) == DOMAIN_MANAGER)
		return 0xff;
	else
		return ap;
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

int __map_gva_to_pfn(struct kvm_vcpu *vcpu, u32 *pgd, gva_t gva, pfn_t pfn,
		     u8 domain, u8 ap, u8 exec)
{
	u32 l1_index;
	u32 *l1_pte, *l2_base, *l2_pte;
	int ret;

	if (page_debug) {
		printk(KERN_DEBUG "   Map gva to pfn at: 0x%08x!\n", vcpu->arch.regs[15]);
		printk(KERN_DEBUG "                 gva: 0x%08x\n", (unsigned int)gva);
		printk(KERN_DEBUG "                 pfn: 0x%08x\n", (unsigned int)pfn);
		printk(KERN_DEBUG "         ap (domain): 0x%x (%u)\n", ap, domain);
	}

	l1_index = gva >> 20;

	if (domain == KVM_SPECIAL_DOMAIN)
		goto skip_domain_check;

	if (l1_index == (SHARED_PAGE_BASE >> 20)) {
		/* This L1 mapping coincides with that of the shared page */
		//XXX Track updates to L1 domain by protecting guest pg. tables
		vcpu->arch.shared_page_guest_domain = domain;
		vcpu->arch.shared_page_shadow_ap[(gva >> 12) & 0xff] = ap;
		ap = convert_domain_to_ap(vcpu, domain, ap);
		if (page_debug) {
			printk(KERN_DEBUG "               ap: 0x%x\n", ap);
		}
		domain = KVM_SPECIAL_DOMAIN;
	} else if (l1_index == (VCPU_HOST_EXCP_BASE(vcpu) >> 20)) {
		/* This L1 mapping coincides with that of the vector page */
		//XXX Track updates to L1 domain by protecting guest pg. tables
		vcpu->arch.vector_page_guest_domain = domain;
		vcpu->arch.vector_page_shadow_ap[(gva >> 12) & 0xff] = ap;
		ap = convert_domain_to_ap(vcpu, domain, ap);
		if (page_debug) {
			printk(KERN_DEBUG "               ap: 0x%x\n", ap);
		}
		domain = KVM_SPECIAL_DOMAIN;
	}

skip_domain_check:
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
		*l1_pte |= ((domain & 0xf) << L1_DOMAIN_SHIFT);
		break;
	case (L1_TYPE_COARSE):
		/* Update the domain of the L1 mapping */
		*l1_pte &= ~L1_DOMAIN_MASK;
		*l1_pte |= ((domain & 0xf) << L1_DOMAIN_SHIFT);

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
	*l2_pte = (pfn << PAGE_SHIFT) | L2_TYPE_SMALL;
	*l2_pte |= 0xc; // Normal memory, cache write back
	*l2_pte &= ~(0x00000ff0);
	*l2_pte |= ap << 4;

	if (page_debug) {
		printk(KERN_DEBUG "        l2_pte: 0x%08x\n", *l2_pte);
	}

	return 0;
}

/*
 * Maps virtual->physical memory in pgd
 *
 * This function will map the page containing the virtual address
 * to the corresponding page number passed in pfn. Overwrites any existing
 * mappings in that place.
 *
 * vcpu:    The virtual CPU
 * pgd:     Pointer to page directory of translation table create mapping
 * gva:     The virtual address
 * pfn:     The physical frame number to map to
 * domain   The access domain for the entry
 * priv_ap: Privileged access permissions (See KVM_AP_XXXXX)
 * user_ap: User mode access permissions (See KVM_AP_XXXXX)
 * exec:    Executable? (1=yes, 0=no)
 */
int map_gva_to_pfn(struct kvm_vcpu *vcpu, u32 *pgd, gva_t gva, pfn_t pfn,
		   u8 domain, u8 priv_ap, u8 user_ap, u8 exec)
{
	u8 ap, calc_ap, i;

	if (priv_ap == KVM_AP_NONE && user_ap != KVM_AP_NONE)
		return -EINVAL;

	if (priv_ap == KVM_AP_RDONLY)
		return -EINVAL;

	calc_ap = calc_aps(priv_ap, user_ap);
	ap = 0;
	for (i = 0; i < 4; i++)
		ap |= calc_ap << (i*2); // Same AP on all subpages
	return __map_gva_to_pfn(vcpu, pgd, gva, pfn, domain, ap, exec);
}

int unmap_gva_section(u32 *pgd, gva_t gva)
{
	u32 *l1_pte;
	pfn_t l2_pfn;

	l1_pte = pgd + (gva >> 20);
	switch ((*l1_pte) & L1_TYPE_MASK) {
	case (L1_TYPE_FAULT):
		/* Already unmapped */
		return 0;
	case (L1_TYPE_COARSE):
		l2_pfn = *l1_pte >> PAGE_SHIFT;
		free_l2_shadow(l2_pfn);
		*l1_pte = 0x0;
		return 0;
	default:
		printk(KERN_ERR "unmap_gva_section: This function supports "
				          "only coarse mappings.\n");
		printk(KERN_ERR "  L1 descriptor: %08x\n", *l1_pte);
		return -EFAULT;
	} 
} 

int unmap_gva(u32 *pgd, gva_t gva)
{
	u32 *l1_pte, *l2_base, *l2_pte;
	int ret;

	l1_pte = pgd + (gva >> 20);
	switch ((*l1_pte) & L1_TYPE_MASK) {
	case (L1_TYPE_FAULT):
		/* Already unmapped */
		return 0;
	case (L1_TYPE_COARSE):
		ret = get_l2_base(*l1_pte, &l2_base);
		if (ret)
			return ret;

		l2_pte = l2_base + ((gva >> 12) & 0xff);
		*l2_pte = 0x0;
		return 0;
	default:
		printk(KERN_ERR "unmap_gva: This function supports "
				          "only coarse mappings.\n");
		printk(KERN_ERR "  L1 descriptor: %08x\n", *l1_pte);
		return -EFAULT;
	} 
} 


/*
 * Will update the L2 AP bits to equal those of the guest mapping with respect
 * to the possible domain values.
 *
 *          @vcpu: The virtual CPU pointer
 *           @pgd: The shadow page table
 * @violating gva: The virtual address that caused us not to be able
 *                 to use the guest native domain in the first place.
 *           @aps: The 256-element array of APs as they would appear in the
 *                 shadow page tables (ie. after convert_domain_to_ap() )
 *       @convert: Whether to convert APs to correspond to a different guest
 *                 domain than in execution DACR
 *           @dom: The domain number used in the guest mapping
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
			ap = convert_domain_to_ap(vcpu, dom, aps[i]);
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


	if (page_debug) {
		printk(KERN_DEBUG "Updating special region ap at: 0x%08x!\n",
			vcpu->arch.regs[15]);
		printk(KERN_DEBUG "              pgd: 0x%08x\n", (unsigned int)pgd);
		printk(KERN_DEBUG "           domain: %u\n", domain);
	}

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

	if (page_debug) {
		printk(KERN_DEBUG "Restoring low vector domain at: 0x%08x!\n",
			vcpu->arch.regs[15]);
		printk(KERN_DEBUG "              pgd: 0x%08x\n", (unsigned int)pgd);
	}

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


/* =========================================================================
 * Interrupt emualtion functions
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
