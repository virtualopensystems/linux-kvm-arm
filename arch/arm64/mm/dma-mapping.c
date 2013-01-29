/*
 * SWIOTLB-based DMA API implementation
 *
 * Copyright (C) 2012 ARM Ltd.
 * Author: Catalin Marinas <catalin.marinas@arm.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <linux/gfp.h>
#include <linux/export.h>
#include <linux/sched.h>
#include <linux/io.h>
#include <linux/iommu.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/dma-mapping.h>
#include <linux/dma-contiguous.h>
#include <linux/vmalloc.h>
#include <linux/swiotlb.h>

#include <asm/cacheflush.h>
#include <asm/tlbflush.h>
#include <asm/dma-iommu.h>

struct dma_map_ops *dma_ops;
EXPORT_SYMBOL(dma_ops);

static void *arm64_swiotlb_alloc_coherent(struct device *dev, size_t size,
					  dma_addr_t *dma_handle, gfp_t flags,
					  struct dma_attrs *attrs)
{
	if (IS_ENABLED(CONFIG_ZONE_DMA32) &&
	    dev->coherent_dma_mask <= DMA_BIT_MASK(32))
		flags |= GFP_DMA32;
	return swiotlb_alloc_coherent(dev, size, dma_handle, flags);
}

static void arm64_swiotlb_free_coherent(struct device *dev, size_t size,
					void *vaddr, dma_addr_t dma_handle,
					struct dma_attrs *attrs)
{
	swiotlb_free_coherent(dev, size, vaddr, dma_handle);
}

static int arm_dma_set_mask(struct device *dev, u64 dma_mask)
{
	if (!dev->dma_mask/* || !dma_supported(dev, dma_mask)*/)
		return -EIO;

	*dev->dma_mask = dma_mask;

	return 0;
}

static struct dma_map_ops arm64_swiotlb_dma_ops = {
	.alloc = arm64_swiotlb_alloc_coherent,
	.free = arm64_swiotlb_free_coherent,
	.map_page = swiotlb_map_page,
	.unmap_page = swiotlb_unmap_page,
	.map_sg = swiotlb_map_sg_attrs,
	.unmap_sg = swiotlb_unmap_sg_attrs,
	.sync_single_for_cpu = swiotlb_sync_single_for_cpu,
	.sync_single_for_device = swiotlb_sync_single_for_device,
	.sync_sg_for_cpu = swiotlb_sync_sg_for_cpu,
	.sync_sg_for_device = swiotlb_sync_sg_for_device,
	.dma_supported = swiotlb_dma_supported,
	.set_dma_mask = arm_dma_set_mask,
	.mapping_error = swiotlb_dma_mapping_error,
};

void __init arm64_swiotlb_init(void)
{
	dma_ops = &arm64_swiotlb_dma_ops;
	swiotlb_init(1);
}

#define PREALLOC_DMA_DEBUG_ENTRIES	4096

static int __init dma_debug_do_init(void)
{
	dma_debug_init(PREALLOC_DMA_DEBUG_ENTRIES);
	return 0;
}
fs_initcall(dma_debug_do_init);

/*
 * Temporary hack to test SMMU driver -- code blindly copied from arch/arm/.
 */

#define VM_ARM_DMA_CONSISTENT  0x20000000
#define dmac_flush_range(s,e)	__flush_dcache_area(s, (e)-(s))

#define DEFAULT_DMA_COHERENT_POOL_SIZE	SZ_256K

static void dmac_map_area(const void *start, size_t sz, int dir)
{
	/* TODO */
}

static void dmac_unmap_area(const void *start, size_t sz, int dir)
{
	/* TODO */
}

static void dma_cache_maint_page(struct page *page, unsigned long offset,
	size_t size, enum dma_data_direction dir,
	void (*op)(const void *, size_t, int))
{
	unsigned long pfn;
	size_t left = size;

	pfn = page_to_pfn(page) + offset / PAGE_SIZE;
	offset %= PAGE_SIZE;

	/*
	 * A single sg entry may refer to multiple physically contiguous
	 * pages.  But we still need to process highmem pages individually.
	 * If highmem is not configured then the bulk of this loop gets
	 * optimized out.
	 */
	do {
		size_t len = left;
		void *vaddr;

		page = pfn_to_page(pfn);
		vaddr = page_address(page) + offset;
		op(vaddr, len, dir);
		offset = 0;
		pfn++;
		left -= len;
	} while (left);
}

static void __dma_page_cpu_to_dev(struct page *page, unsigned long off,
	size_t size, enum dma_data_direction dir)
{
	dma_cache_maint_page(page, off, size, dir, dmac_map_area);
}

static void __dma_page_dev_to_cpu(struct page *page, unsigned long off,
	size_t size, enum dma_data_direction dir)
{
	dma_cache_maint_page(page, off, size, dir, dmac_unmap_area);

	/*
	 * Mark the D-cache clean for this page to avoid extra flushing.
	 */
	if (dir != DMA_TO_DEVICE && off == 0 && size >= PAGE_SIZE)
		set_bit(PG_dcache_clean, &page->flags);
}

static int __dma_update_pte(pte_t *pte, pgtable_t token, unsigned long addr,
			    void *data)
{
	struct page *page = virt_to_page(addr);
	pgprot_t prot = *(pgprot_t *)data;

	set_pte(pte, mk_pte(page, prot));
	return 0;
}

static void __dma_remap(struct page *page, size_t size, pgprot_t prot)
{
	unsigned long start = (unsigned long) page_address(page);
	unsigned end = start + size;

	apply_to_page_range(&init_mm, start, size, __dma_update_pte, &prot);
	dsb();
	flush_tlb_kernel_range(start, end);
}

static void *
__dma_alloc_remap(struct page *page, size_t size, gfp_t gfp, pgprot_t prot,
	const void *caller)
{
	struct vm_struct *area;
	unsigned long addr;

	/*
	 * DMA allocation can be mapped to user space, so lets
	 * set VM_USERMAP flags too.
	 */
	area = get_vm_area_caller(size, VM_ARM_DMA_CONSISTENT | VM_USERMAP,
				  caller);
	if (!area)
		return NULL;
	addr = (unsigned long)area->addr;
	area->phys_addr = __pfn_to_phys(page_to_pfn(page));

	if (ioremap_page_range(addr, addr + size, area->phys_addr, prot)) {
		vunmap((void *)addr);
		return NULL;
	}
	return (void *)addr;
}

struct dma_pool {
	size_t size;
	spinlock_t lock;
	unsigned long *bitmap;
	unsigned long nr_pages;
	void *vaddr;
	struct page **pages;
};

static struct dma_pool atomic_pool = {
	.size = DEFAULT_DMA_COHERENT_POOL_SIZE,
};

static void __dma_clear_buffer(struct page *page, size_t size)
{
	/*
	 * Ensure that the allocated pages are zeroed, and that any data
	 * lurking in the kernel direct-mapped region is invalidated.
	 */
	void *ptr = page_address(page);
	memset(ptr, 0, size);
	dmac_flush_range(ptr, ptr + size);
}

static struct page *__dma_alloc_buffer(struct device *dev, size_t size, gfp_t gfp)
{
	unsigned long order = get_order(size);
	struct page *page, *p, *e;

	page = alloc_pages(gfp, order);
	if (!page)
		return NULL;

	/*
	 * Now split the huge page and free the excess pages
	 */
	split_page(page, order);
	for (p = page + (size >> PAGE_SHIFT), e = page + (1 << order); p < e; p++)
		__free_page(p);

	__dma_clear_buffer(page, size);

	return page;
}

/*
 * Free a DMA buffer.  'size' must be page aligned.
 */
static void __dma_free_buffer(struct page *page, size_t size)
{
	struct page *e = page + (size >> PAGE_SHIFT);

	while (page < e) {
		__free_page(page);
		page++;
	}
}

static void *__alloc_remap_buffer(struct device *dev, size_t size, gfp_t gfp,
				 pgprot_t prot, struct page **ret_page,
				 const void *caller)
{
	struct page *page;
	void *ptr;
	page = __dma_alloc_buffer(dev, size, gfp);
	if (!page)
		return NULL;

	ptr = __dma_alloc_remap(page, size, gfp, prot, caller);
	if (!ptr) {
		__dma_free_buffer(page, size);
		return NULL;
	}

	*ret_page = page;
	return ptr;
}

static void *__alloc_from_pool(size_t size, struct page **ret_page)
{
	struct dma_pool *pool = &atomic_pool;
	unsigned int count = PAGE_ALIGN(size) >> PAGE_SHIFT;
	unsigned int pageno;
	unsigned long flags;
	void *ptr = NULL;
	unsigned long align_mask;

	if (!pool->vaddr) {
		WARN(1, "coherent pool not initialised!\n");
		return NULL;
	}

	/*
	 * Align the region allocation - allocations from pool are rather
	 * small, so align them to their order in pages, minimum is a page
	 * size. This helps reduce fragmentation of the DMA space.
	 */
	align_mask = (1 << get_order(size)) - 1;

	spin_lock_irqsave(&pool->lock, flags);
	pageno = bitmap_find_next_zero_area(pool->bitmap, pool->nr_pages,
					    0, count, align_mask);
	if (pageno < pool->nr_pages) {
		bitmap_set(pool->bitmap, pageno, count);
		ptr = pool->vaddr + PAGE_SIZE * pageno;
		*ret_page = pool->pages[pageno];
	} else {
		pr_err_once("ERROR: %u KiB atomic DMA coherent pool is too small!\n"
			    "Please increase it with coherent_pool= kernel parameter!\n",
			    (unsigned)pool->size / 1024);
	}
	spin_unlock_irqrestore(&pool->lock, flags);

	return ptr;
}

static bool __in_atomic_pool(void *start, size_t size)
{
	struct dma_pool *pool = &atomic_pool;
	void *end = start + size;
	void *pool_start = pool->vaddr;
	void *pool_end = pool->vaddr + pool->size;

	if (start < pool_start || start >= pool_end)
		return false;

	if (end <= pool_end)
		return true;

	WARN(1, "Wrong coherent size(%p-%p) from atomic pool(%p-%p)\n",
	     start, end - 1, pool_start, pool_end - 1);

	return false;
}

static int __free_from_pool(void *start, size_t size)
{
	struct dma_pool *pool = &atomic_pool;
	unsigned long pageno, count;
	unsigned long flags;

	if (!__in_atomic_pool(start, size))
		return 0;

	pageno = (start - pool->vaddr) >> PAGE_SHIFT;
	count = size >> PAGE_SHIFT;

	spin_lock_irqsave(&pool->lock, flags);
	bitmap_clear(pool->bitmap, pageno, count);
	spin_unlock_irqrestore(&pool->lock, flags);

	return 1;
}

static void *__alloc_from_contiguous(struct device *dev, size_t size,
				     pgprot_t prot, struct page **ret_page,
				     const void *caller)
{
	unsigned long order = get_order(size);
	size_t count = size >> PAGE_SHIFT;
	struct page *page;
	void *ptr;

	page = dma_alloc_from_contiguous(dev, count, order);
	if (!page)
		return NULL;

	__dma_clear_buffer(page, size);

	if (PageHighMem(page)) {
		ptr = __dma_alloc_remap(page, size, GFP_KERNEL, prot, caller);
		if (!ptr) {
			dma_release_from_contiguous(dev, page, count);
			return NULL;
		}
	} else {
		__dma_remap(page, size, prot);
		ptr = page_address(page);
	}
	*ret_page = page;
	return ptr;
}

static inline pgprot_t __get_dma_pgprot(struct dma_attrs *attrs, pgprot_t prot)
{
	prot = dma_get_attr(DMA_ATTR_WRITE_COMBINE, attrs) ?
			    pgprot_writecombine(prot) :
			    pgprot_dmacoherent(prot);
	return prot;
}

static int __init atomic_pool_init(void)
{
	struct dma_pool *pool = &atomic_pool;
	pgprot_t prot = pgprot_dmacoherent(pgprot_default);
	gfp_t gfp = GFP_KERNEL | GFP_DMA;
	unsigned long nr_pages = pool->size >> PAGE_SHIFT;
	unsigned long *bitmap;
	struct page *page;
	struct page **pages;
	void *ptr;
	int bitmap_size = BITS_TO_LONGS(nr_pages) * sizeof(long);

	bitmap = kzalloc(bitmap_size, GFP_KERNEL);
	if (!bitmap)
		goto no_bitmap;

	pages = kzalloc(nr_pages * sizeof(struct page *), GFP_KERNEL);
	if (!pages)
		goto no_pages;

	if (IS_ENABLED(CONFIG_CMA))
		ptr = __alloc_from_contiguous(NULL, pool->size, prot, &page,
					      atomic_pool_init);
	else
		ptr = __alloc_remap_buffer(NULL, pool->size, gfp, prot, &page,
					   atomic_pool_init);
	if (ptr) {
		int i;

		for (i = 0; i < nr_pages; i++)
			pages[i] = page + i;

		spin_lock_init(&pool->lock);
		pool->vaddr = ptr;
		pool->pages = pages;
		pool->bitmap = bitmap;
		pool->nr_pages = nr_pages;
		pr_info("DMA: preallocated %u KiB pool for atomic coherent allocations\n",
		       (unsigned)pool->size / 1024);
		return 0;
	}

	kfree(pages);
no_pages:
	kfree(bitmap);
no_bitmap:
	pr_err("DMA: failed to allocate %u KiB pool for atomic coherent allocation\n",
	       (unsigned)pool->size / 1024);
	return -ENOMEM;
}
postcore_initcall(atomic_pool_init);

static inline dma_addr_t __alloc_iova(struct dma_iommu_mapping *mapping,
				      size_t size)
{
	unsigned int order = get_order(size);
	unsigned int align = 0;
	unsigned int count, start;
	unsigned long flags;

	if (order > 8/*CONFIG_ARM_DMA_IOMMU_ALIGNMENT*/)
		order = 8/*CONFIG_ARM_DMA_IOMMU_ALIGNMENT*/;

	count = ((PAGE_ALIGN(size) >> PAGE_SHIFT) +
		 (1 << mapping->order) - 1) >> mapping->order;

	if (order > mapping->order)
		align = (1 << (order - mapping->order)) - 1;

	spin_lock_irqsave(&mapping->lock, flags);
	start = bitmap_find_next_zero_area(mapping->bitmap, mapping->bits, 0,
					   count, align);
	if (start > mapping->bits) {
		spin_unlock_irqrestore(&mapping->lock, flags);
		return DMA_ERROR_CODE;
	}

	bitmap_set(mapping->bitmap, start, count);
	spin_unlock_irqrestore(&mapping->lock, flags);

	return mapping->base + (start << (mapping->order + PAGE_SHIFT));
}

static inline void __free_iova(struct dma_iommu_mapping *mapping,
			       dma_addr_t addr, size_t size)
{
	unsigned int start = (addr - mapping->base) >>
			     (mapping->order + PAGE_SHIFT);
	unsigned int count = ((size >> PAGE_SHIFT) +
			      (1 << mapping->order) - 1) >> mapping->order;
	unsigned long flags;

	spin_lock_irqsave(&mapping->lock, flags);
	bitmap_clear(mapping->bitmap, start, count);
	spin_unlock_irqrestore(&mapping->lock, flags);
}

static struct page **__iommu_alloc_buffer(struct device *dev, size_t size,
					  gfp_t gfp, struct dma_attrs *attrs)
{
	struct page **pages;
	int count = size >> PAGE_SHIFT;
	int array_size = count * sizeof(struct page *);
	int i = 0;

	if (array_size <= PAGE_SIZE)
		pages = kzalloc(array_size, gfp);
	else
		pages = vzalloc(array_size);
	if (!pages)
		return NULL;

	if (dma_get_attr(DMA_ATTR_FORCE_CONTIGUOUS, attrs))
	{
		unsigned long order = get_order(size);
		struct page *page;

		page = dma_alloc_from_contiguous(dev, count, order);
		if (!page)
			goto error;

		__dma_clear_buffer(page, size);

		for (i = 0; i < count; i++)
			pages[i] = page + i;

		return pages;
	}

	/*
	 * IOMMU can map any pages, so himem can also be used here
	 */
	gfp |= __GFP_NOWARN | __GFP_HIGHMEM;

	while (count) {
		int j, order = __fls(count);

		pages[i] = alloc_pages(gfp, order);
		while (!pages[i] && order)
			pages[i] = alloc_pages(gfp, --order);
		if (!pages[i])
			goto error;

		if (order) {
			split_page(pages[i], order);
			j = 1 << order;
			while (--j)
				pages[i + j] = pages[i] + j;
		}

		__dma_clear_buffer(pages[i], PAGE_SIZE << order);
		i += 1 << order;
		count -= 1 << order;
	}

	return pages;
error:
	while (i--)
		if (pages[i])
			__free_pages(pages[i], 0);
	if (array_size <= PAGE_SIZE)
		kfree(pages);
	else
		vfree(pages);
	return NULL;
}

static int __iommu_free_buffer(struct device *dev, struct page **pages,
			       size_t size, struct dma_attrs *attrs)
{
	int count = size >> PAGE_SHIFT;
	int array_size = count * sizeof(struct page *);
	int i;

	if (dma_get_attr(DMA_ATTR_FORCE_CONTIGUOUS, attrs)) {
		dma_release_from_contiguous(dev, pages[0], count);
	} else {
		for (i = 0; i < count; i++)
			if (pages[i])
				__free_pages(pages[i], 0);
	}

	if (array_size <= PAGE_SIZE)
		kfree(pages);
	else
		vfree(pages);
	return 0;
}

/*
 * Create a CPU mapping for a specified pages
 */
static void *
__iommu_alloc_remap(struct page **pages, size_t size, gfp_t gfp, pgprot_t prot,
		    const void *caller)
{
	unsigned int i, nr_pages = PAGE_ALIGN(size) >> PAGE_SHIFT;
	struct vm_struct *area;
	unsigned long p;

	area = get_vm_area_caller(size, VM_ARM_DMA_CONSISTENT | VM_USERMAP,
				  caller);
	if (!area)
		return NULL;

	area->pages = pages;
	area->nr_pages = nr_pages;
	p = (unsigned long)area->addr;

	for (i = 0; i < nr_pages; i++) {
		phys_addr_t phys = __pfn_to_phys(page_to_pfn(pages[i]));
		if (ioremap_page_range(p, p + PAGE_SIZE, phys, prot))
			goto err;
		p += PAGE_SIZE;
	}
	return area->addr;
err:
	unmap_kernel_range((unsigned long)area->addr, size);
	vunmap(area->addr);
	return NULL;
}

/*
 * Create a mapping in device IO address space for specified pages
 */
static dma_addr_t
__iommu_create_mapping(struct device *dev, struct page **pages, size_t size)
{
	struct dma_iommu_mapping *mapping = dev->archdata.mapping;
	unsigned int count = PAGE_ALIGN(size) >> PAGE_SHIFT;
	dma_addr_t dma_addr, iova, ret = DMA_ERROR_CODE;
	int i;

	dma_addr = __alloc_iova(mapping, size);
	if (dma_addr == DMA_ERROR_CODE)
		return dma_addr;

	iova = dma_addr;
	for (i = 0; i < count; ) {
		unsigned int next_pfn = page_to_pfn(pages[i]) + 1;
		phys_addr_t phys = page_to_phys(pages[i]);
		unsigned int len, j;

		for (j = i + 1; j < count; j++, next_pfn++)
			if (page_to_pfn(pages[j]) != next_pfn)
				break;

		len = (j - i) << PAGE_SHIFT;
		ret = iommu_map(mapping->domain, iova, phys, len, 0);
		if (ret < 0)
			goto fail;
		iova += len;
		i = j;
	}
	return dma_addr;
fail:
	iommu_unmap(mapping->domain, dma_addr, iova-dma_addr);
	__free_iova(mapping, dma_addr, size);
	return DMA_ERROR_CODE;
}

static int __iommu_remove_mapping(struct device *dev, dma_addr_t iova, size_t size)
{
	struct dma_iommu_mapping *mapping = dev->archdata.mapping;

	/*
	 * add optional in-page offset from iova to size and align
	 * result to page size
	 */
	size = PAGE_ALIGN((iova & ~PAGE_MASK) + size);
	iova &= PAGE_MASK;

	iommu_unmap(mapping->domain, iova, size);
	__free_iova(mapping, iova, size);
	return 0;
}

static struct page **__atomic_get_pages(void *addr)
{
	struct dma_pool *pool = &atomic_pool;
	struct page **pages = pool->pages;
	int offs = (addr - pool->vaddr) >> PAGE_SHIFT;

	return pages + offs;
}

static struct page **__iommu_get_pages(void *cpu_addr, struct dma_attrs *attrs)
{
	struct vm_struct *area;

	if (__in_atomic_pool(cpu_addr, PAGE_SIZE))
		return __atomic_get_pages(cpu_addr);

	if (dma_get_attr(DMA_ATTR_NO_KERNEL_MAPPING, attrs))
		return cpu_addr;

	area = find_vm_area(cpu_addr);
	if (area && (area->flags & VM_ARM_DMA_CONSISTENT))
		return area->pages;
	return NULL;
}

static void *__iommu_alloc_atomic(struct device *dev, size_t size,
				  dma_addr_t *handle)
{
	struct page *page;
	void *addr;

	addr = __alloc_from_pool(size, &page);
	if (!addr)
		return NULL;

	*handle = __iommu_create_mapping(dev, &page, size);
	if (*handle == DMA_ERROR_CODE)
		goto err_mapping;

	return addr;

err_mapping:
	__free_from_pool(addr, size);
	return NULL;
}

static void __iommu_free_atomic(struct device *dev, void *cpu_addr,
				dma_addr_t handle, size_t size)
{
	__iommu_remove_mapping(dev, handle, size);
	__free_from_pool(cpu_addr, size);
}

static void *arm_iommu_alloc_attrs(struct device *dev, size_t size,
	    dma_addr_t *handle, gfp_t gfp, struct dma_attrs *attrs)
{
	pgprot_t prot = __get_dma_pgprot(attrs, pgprot_default);
	struct page **pages;
	void *addr = NULL;

	*handle = DMA_ERROR_CODE;
	size = PAGE_ALIGN(size);

	if (gfp & GFP_ATOMIC)
		return __iommu_alloc_atomic(dev, size, handle);

	pages = __iommu_alloc_buffer(dev, size, gfp, attrs);
	if (!pages)
		return NULL;

	*handle = __iommu_create_mapping(dev, pages, size);
	if (*handle == DMA_ERROR_CODE)
		goto err_buffer;

	if (dma_get_attr(DMA_ATTR_NO_KERNEL_MAPPING, attrs))
		return pages;

	addr = __iommu_alloc_remap(pages, size, gfp, prot,
				   __builtin_return_address(0));
	if (!addr)
		goto err_mapping;

	return addr;

err_mapping:
	__iommu_remove_mapping(dev, *handle, size);
err_buffer:
	__iommu_free_buffer(dev, pages, size, attrs);
	return NULL;
}

static int arm_iommu_mmap_attrs(struct device *dev, struct vm_area_struct *vma,
		    void *cpu_addr, dma_addr_t dma_addr, size_t size,
		    struct dma_attrs *attrs)
{
	unsigned long uaddr = vma->vm_start;
	unsigned long usize = vma->vm_end - vma->vm_start;
	struct page **pages = __iommu_get_pages(cpu_addr, attrs);

	vma->vm_page_prot = __get_dma_pgprot(attrs, vma->vm_page_prot);

	if (!pages)
		return -ENXIO;

	do {
		int ret = vm_insert_page(vma, uaddr, *pages++);
		if (ret) {
			pr_err("Remapping memory failed: %d\n", ret);
			return ret;
		}
		uaddr += PAGE_SIZE;
		usize -= PAGE_SIZE;
	} while (usize > 0);

	return 0;
}

/*
 * free a page as defined by the above mapping.
 * Must not be called with IRQs disabled.
 */
void arm_iommu_free_attrs(struct device *dev, size_t size, void *cpu_addr,
			  dma_addr_t handle, struct dma_attrs *attrs)
{
	struct page **pages = __iommu_get_pages(cpu_addr, attrs);
	size = PAGE_ALIGN(size);

	if (!pages) {
		WARN(1, "trying to free invalid coherent area: %p\n", cpu_addr);
		return;
	}

	if (__in_atomic_pool(cpu_addr, size)) {
		__iommu_free_atomic(dev, cpu_addr, handle, size);
		return;
	}

	if (!dma_get_attr(DMA_ATTR_NO_KERNEL_MAPPING, attrs)) {
		unmap_kernel_range((unsigned long)cpu_addr, size);
		vunmap(cpu_addr);
	}

	__iommu_remove_mapping(dev, handle, size);
	__iommu_free_buffer(dev, pages, size, attrs);
}

static int arm_iommu_get_sgtable(struct device *dev, struct sg_table *sgt,
				 void *cpu_addr, dma_addr_t dma_addr,
				 size_t size, struct dma_attrs *attrs)
{
	unsigned int count = PAGE_ALIGN(size) >> PAGE_SHIFT;
	struct page **pages = __iommu_get_pages(cpu_addr, attrs);

	if (!pages)
		return -ENXIO;

	return sg_alloc_table_from_pages(sgt, pages, count, 0, size,
					 GFP_KERNEL);
}

/*
 * Map a part of the scatter-gather list into contiguous io address space
 */
static int __map_sg_chunk(struct device *dev, struct scatterlist *sg,
			  size_t size, dma_addr_t *handle,
			  enum dma_data_direction dir, struct dma_attrs *attrs,
			  bool is_coherent)
{
	struct dma_iommu_mapping *mapping = dev->archdata.mapping;
	dma_addr_t iova, iova_base;
	int ret = 0;
	unsigned int count;
	struct scatterlist *s;

	size = PAGE_ALIGN(size);
	*handle = DMA_ERROR_CODE;

	iova_base = iova = __alloc_iova(mapping, size);
	if (iova == DMA_ERROR_CODE)
		return -ENOMEM;

	for (count = 0, s = sg; count < (size >> PAGE_SHIFT); s = sg_next(s)) {
		phys_addr_t phys = page_to_phys(sg_page(s));
		unsigned int len = PAGE_ALIGN(s->offset + s->length);

		if (!is_coherent &&
			!dma_get_attr(DMA_ATTR_SKIP_CPU_SYNC, attrs))
			__dma_page_cpu_to_dev(sg_page(s), s->offset, s->length, dir);

		ret = iommu_map(mapping->domain, iova, phys, len, 0);
		if (ret < 0)
			goto fail;
		count += len >> PAGE_SHIFT;
		iova += len;
	}
	*handle = iova_base;

	return 0;
fail:
	iommu_unmap(mapping->domain, iova_base, count * PAGE_SIZE);
	__free_iova(mapping, iova_base, size);
	return ret;
}

static int __iommu_map_sg(struct device *dev, struct scatterlist *sg, int nents,
		     enum dma_data_direction dir, struct dma_attrs *attrs,
		     bool is_coherent)
{
	struct scatterlist *s = sg, *dma = sg, *start = sg;
	int i, count = 0;
	unsigned int offset = s->offset;
	unsigned int size = s->offset + s->length;
	unsigned int max = dma_get_max_seg_size(dev);

	for (i = 1; i < nents; i++) {
		s = sg_next(s);

		s->dma_address = DMA_ERROR_CODE;
		s->dma_length = 0;

		if (s->offset || (size & ~PAGE_MASK) || size + s->length > max) {
			if (__map_sg_chunk(dev, start, size, &dma->dma_address,
			    dir, attrs, is_coherent) < 0)
				goto bad_mapping;

			dma->dma_address += offset;
			dma->dma_length = size - offset;

			size = offset = s->offset;
			start = s;
			dma = sg_next(dma);
			count += 1;
		}
		size += s->length;
	}
	if (__map_sg_chunk(dev, start, size, &dma->dma_address, dir, attrs,
		is_coherent) < 0)
		goto bad_mapping;

	dma->dma_address += offset;
	dma->dma_length = size - offset;

	return count+1;

bad_mapping:
	for_each_sg(sg, s, count, i)
		__iommu_remove_mapping(dev, sg_dma_address(s), sg_dma_len(s));
	return 0;
}

/**
 * arm_coherent_iommu_map_sg - map a set of SG buffers for streaming mode DMA
 * @dev: valid struct device pointer
 * @sg: list of buffers
 * @nents: number of buffers to map
 * @dir: DMA transfer direction
 *
 * Map a set of i/o coherent buffers described by scatterlist in streaming
 * mode for DMA. The scatter gather list elements are merged together (if
 * possible) and tagged with the appropriate dma address and length. They are
 * obtained via sg_dma_{address,length}.
 */
int arm_coherent_iommu_map_sg(struct device *dev, struct scatterlist *sg,
		int nents, enum dma_data_direction dir, struct dma_attrs *attrs)
{
	return __iommu_map_sg(dev, sg, nents, dir, attrs, true);
}

/**
 * arm_iommu_map_sg - map a set of SG buffers for streaming mode DMA
 * @dev: valid struct device pointer
 * @sg: list of buffers
 * @nents: number of buffers to map
 * @dir: DMA transfer direction
 *
 * Map a set of buffers described by scatterlist in streaming mode for DMA.
 * The scatter gather list elements are merged together (if possible) and
 * tagged with the appropriate dma address and length. They are obtained via
 * sg_dma_{address,length}.
 */
int arm_iommu_map_sg(struct device *dev, struct scatterlist *sg,
		int nents, enum dma_data_direction dir, struct dma_attrs *attrs)
{
	return __iommu_map_sg(dev, sg, nents, dir, attrs, false);
}

static void __iommu_unmap_sg(struct device *dev, struct scatterlist *sg,
		int nents, enum dma_data_direction dir, struct dma_attrs *attrs,
		bool is_coherent)
{
	struct scatterlist *s;
	int i;

	for_each_sg(sg, s, nents, i) {
		if (sg_dma_len(s))
			__iommu_remove_mapping(dev, sg_dma_address(s),
					       sg_dma_len(s));
		if (!is_coherent &&
		    !dma_get_attr(DMA_ATTR_SKIP_CPU_SYNC, attrs))
			__dma_page_dev_to_cpu(sg_page(s), s->offset,
					      s->length, dir);
	}
}

/**
 * arm_coherent_iommu_unmap_sg - unmap a set of SG buffers mapped by dma_map_sg
 * @dev: valid struct device pointer
 * @sg: list of buffers
 * @nents: number of buffers to unmap (same as was passed to dma_map_sg)
 * @dir: DMA transfer direction (same as was passed to dma_map_sg)
 *
 * Unmap a set of streaming mode DMA translations.  Again, CPU access
 * rules concerning calls here are the same as for dma_unmap_single().
 */
void arm_coherent_iommu_unmap_sg(struct device *dev, struct scatterlist *sg,
		int nents, enum dma_data_direction dir, struct dma_attrs *attrs)
{
	__iommu_unmap_sg(dev, sg, nents, dir, attrs, true);
}

/**
 * arm_iommu_unmap_sg - unmap a set of SG buffers mapped by dma_map_sg
 * @dev: valid struct device pointer
 * @sg: list of buffers
 * @nents: number of buffers to unmap (same as was passed to dma_map_sg)
 * @dir: DMA transfer direction (same as was passed to dma_map_sg)
 *
 * Unmap a set of streaming mode DMA translations.  Again, CPU access
 * rules concerning calls here are the same as for dma_unmap_single().
 */
void arm_iommu_unmap_sg(struct device *dev, struct scatterlist *sg, int nents,
			enum dma_data_direction dir, struct dma_attrs *attrs)
{
	__iommu_unmap_sg(dev, sg, nents, dir, attrs, false);
}

/**
 * arm_iommu_sync_sg_for_cpu
 * @dev: valid struct device pointer
 * @sg: list of buffers
 * @nents: number of buffers to map (returned from dma_map_sg)
 * @dir: DMA transfer direction (same as was passed to dma_map_sg)
 */
void arm_iommu_sync_sg_for_cpu(struct device *dev, struct scatterlist *sg,
			int nents, enum dma_data_direction dir)
{
	struct scatterlist *s;
	int i;

	for_each_sg(sg, s, nents, i)
		__dma_page_dev_to_cpu(sg_page(s), s->offset, s->length, dir);

}

/**
 * arm_iommu_sync_sg_for_device
 * @dev: valid struct device pointer
 * @sg: list of buffers
 * @nents: number of buffers to map (returned from dma_map_sg)
 * @dir: DMA transfer direction (same as was passed to dma_map_sg)
 */
void arm_iommu_sync_sg_for_device(struct device *dev, struct scatterlist *sg,
			int nents, enum dma_data_direction dir)
{
	struct scatterlist *s;
	int i;

	for_each_sg(sg, s, nents, i)
		__dma_page_cpu_to_dev(sg_page(s), s->offset, s->length, dir);
}


/**
 * arm_coherent_iommu_map_page
 * @dev: valid struct device pointer
 * @page: page that buffer resides in
 * @offset: offset into page for start of buffer
 * @size: size of buffer to map
 * @dir: DMA transfer direction
 *
 * Coherent IOMMU aware version of arm_dma_map_page()
 */
static dma_addr_t arm_coherent_iommu_map_page(struct device *dev, struct page *page,
	     unsigned long offset, size_t size, enum dma_data_direction dir,
	     struct dma_attrs *attrs)
{
	struct dma_iommu_mapping *mapping = dev->archdata.mapping;
	dma_addr_t dma_addr;
	int ret, prot, len = PAGE_ALIGN(size + offset);

	dma_addr = __alloc_iova(mapping, len);
	if (dma_addr == DMA_ERROR_CODE)
		return dma_addr;

	switch (dir) {
	case DMA_BIDIRECTIONAL:
		prot = IOMMU_READ | IOMMU_WRITE;
		break;
	case DMA_TO_DEVICE:
		prot = IOMMU_READ;
		break;
	case DMA_FROM_DEVICE:
		prot = IOMMU_WRITE;
		break;
	default:
		prot = 0;
	}

	ret = iommu_map(mapping->domain, dma_addr, page_to_phys(page), len, prot);
	if (ret < 0)
		goto fail;

	return dma_addr + offset;
fail:
	__free_iova(mapping, dma_addr, len);
	return DMA_ERROR_CODE;
}

/**
 * arm_iommu_map_page
 * @dev: valid struct device pointer
 * @page: page that buffer resides in
 * @offset: offset into page for start of buffer
 * @size: size of buffer to map
 * @dir: DMA transfer direction
 *
 * IOMMU aware version of arm_dma_map_page()
 */
static dma_addr_t arm_iommu_map_page(struct device *dev, struct page *page,
	     unsigned long offset, size_t size, enum dma_data_direction dir,
	     struct dma_attrs *attrs)
{
	dma_addr_t ret;

	if (!dma_get_attr(DMA_ATTR_SKIP_CPU_SYNC, attrs))
		__dma_page_cpu_to_dev(page, offset, size, dir);

	ret = arm_coherent_iommu_map_page(dev, page, offset, size, dir, attrs);
	return ret;
}

/**
 * arm_iommu_unmap_page
 * @dev: valid struct device pointer
 * @handle: DMA address of buffer
 * @size: size of buffer (same as passed to dma_map_page)
 * @dir: DMA transfer direction (same as passed to dma_map_page)
 *
 * IOMMU aware version of arm_dma_unmap_page()
 */
static void arm_iommu_unmap_page(struct device *dev, dma_addr_t handle,
		size_t size, enum dma_data_direction dir,
		struct dma_attrs *attrs)
{
	struct dma_iommu_mapping *mapping = dev->archdata.mapping;
	dma_addr_t iova = handle & PAGE_MASK;
	struct page *page = phys_to_page(iommu_iova_to_phys(mapping->domain, iova));
	int offset = handle & ~PAGE_MASK;
	int len = PAGE_ALIGN(size + offset);

	if (!iova)
		return;

	if (!dma_get_attr(DMA_ATTR_SKIP_CPU_SYNC, attrs))
		__dma_page_dev_to_cpu(page, offset, size, dir);

	iommu_unmap(mapping->domain, iova, len);
	__free_iova(mapping, iova, len);
}

static void arm_iommu_sync_single_for_cpu(struct device *dev,
		dma_addr_t handle, size_t size, enum dma_data_direction dir)
{
	struct dma_iommu_mapping *mapping = dev->archdata.mapping;
	dma_addr_t iova = handle & PAGE_MASK;
	struct page *page = phys_to_page(iommu_iova_to_phys(mapping->domain, iova));
	unsigned int offset = handle & ~PAGE_MASK;

	if (!iova)
		return;

	__dma_page_dev_to_cpu(page, offset, size, dir);
}

static void arm_iommu_sync_single_for_device(struct device *dev,
		dma_addr_t handle, size_t size, enum dma_data_direction dir)
{
	struct dma_iommu_mapping *mapping = dev->archdata.mapping;
	dma_addr_t iova = handle & PAGE_MASK;
	struct page *page = phys_to_page(iommu_iova_to_phys(mapping->domain, iova));
	unsigned int offset = handle & ~PAGE_MASK;

	if (!iova)
		return;

	__dma_page_cpu_to_dev(page, offset, size, dir);
}

static int arm_dma_supported(struct device *dev, u64 dma_mask)
{
	/* Bah, let's say we can DMA everywhere. */
	return 1;
}

struct dma_map_ops iommu_ops = {
	.alloc		= arm_iommu_alloc_attrs,
	.free		= arm_iommu_free_attrs,
	.mmap		= arm_iommu_mmap_attrs,
	.get_sgtable	= arm_iommu_get_sgtable,

	.map_page		= arm_iommu_map_page,
	.unmap_page		= arm_iommu_unmap_page,
	.sync_single_for_cpu	= arm_iommu_sync_single_for_cpu,
	.sync_single_for_device	= arm_iommu_sync_single_for_device,

	.map_sg			= arm_iommu_map_sg,
	.unmap_sg		= arm_iommu_unmap_sg,
	.sync_sg_for_cpu	= arm_iommu_sync_sg_for_cpu,
	.sync_sg_for_device	= arm_iommu_sync_sg_for_device,

	.dma_supported		= arm_dma_supported,
	.set_dma_mask		= arm_dma_set_mask,
};

struct dma_iommu_mapping *
arm_iommu_create_mapping(struct bus_type *bus, dma_addr_t base, dma_addr_t size,
			 int order)
{
	u64 count = size >> (PAGE_SHIFT + order);
	unsigned int bitmap_size = BITS_TO_LONGS(count) * sizeof(long);
	struct dma_iommu_mapping *mapping;
	int err = -ENOMEM;

	if (!count)
		return ERR_PTR(-EINVAL);

	mapping = kzalloc(sizeof(struct dma_iommu_mapping), GFP_KERNEL);
	if (!mapping)
		goto err;

	mapping->bitmap = kzalloc(bitmap_size, GFP_KERNEL);
	if (!mapping->bitmap)
		goto err2;

	mapping->base = base;
	mapping->bits = BITS_PER_BYTE * bitmap_size;
	mapping->order = order;
	spin_lock_init(&mapping->lock);

	mapping->domain = iommu_domain_alloc(bus);
	if (!mapping->domain)
		goto err3;

	kref_init(&mapping->kref);
	return mapping;
err3:
	kfree(mapping->bitmap);
err2:
	kfree(mapping);
err:
	return ERR_PTR(err);
}
EXPORT_SYMBOL_GPL(arm_iommu_create_mapping);

static void release_iommu_mapping(struct kref *kref)
{
	struct dma_iommu_mapping *mapping =
		container_of(kref, struct dma_iommu_mapping, kref);

	iommu_domain_free(mapping->domain);
	kfree(mapping->bitmap);
	kfree(mapping);
}

void arm_iommu_release_mapping(struct dma_iommu_mapping *mapping)
{
	if (mapping)
		kref_put(&mapping->kref, release_iommu_mapping);
}
EXPORT_SYMBOL_GPL(arm_iommu_release_mapping);

int arm_iommu_attach_device(struct device *dev,
			    struct dma_iommu_mapping *mapping)
{
	int err;

	err = iommu_attach_device(mapping->domain, dev);
	if (err)
		return err;

	kref_get(&mapping->kref);
	dev->archdata.mapping = mapping;
	set_dma_ops(dev, &iommu_ops);

	pr_debug("Attached IOMMU controller to %s device.\n", dev_name(dev));
	return 0;
}
EXPORT_SYMBOL_GPL(arm_iommu_attach_device);

void arm_iommu_detach_device(struct device *dev)
{
	struct dma_iommu_mapping *mapping;

	mapping = to_dma_iommu_mapping(dev);
	if (!mapping) {
		dev_warn(dev, "Not attached\n");
		return;
	}

	iommu_detach_device(mapping->domain, dev);
	kref_put(&mapping->kref, release_iommu_mapping);
	dev->archdata.mapping = NULL;
	set_dma_ops(dev, NULL);

	pr_debug("Detached IOMMU controller from %s device.\n", dev_name(dev));
}
EXPORT_SYMBOL_GPL(arm_iommu_detach_device);
