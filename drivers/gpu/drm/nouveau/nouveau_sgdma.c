#include "drmP.h"
#include "nouveau_drv.h"
#include <linux/pagemap.h>
#include <linux/slab.h>

#define NV_CTXDMA_PAGE_SHIFT 12
#define NV_CTXDMA_PAGE_SIZE  (1 << NV_CTXDMA_PAGE_SHIFT)
#define NV_CTXDMA_PAGE_MASK  (NV_CTXDMA_PAGE_SIZE - 1)

struct nouveau_sgdma_be {
	struct ttm_backend backend;
	struct drm_device *dev;

	dma_addr_t *pages;
	unsigned nr_pages;

	u64 offset;
	bool bound;
};

static int
nouveau_sgdma_populate(struct ttm_backend *be, unsigned long num_pages,
		       struct page **pages, struct page *dummy_read_page)
{
	struct nouveau_sgdma_be *nvbe = (struct nouveau_sgdma_be *)be;
	struct drm_device *dev = nvbe->dev;

	NV_DEBUG(nvbe->dev, "num_pages = %ld\n", num_pages);

	if (nvbe->pages)
		return -EINVAL;

	nvbe->pages = kmalloc(sizeof(dma_addr_t) * num_pages, GFP_KERNEL);
	if (!nvbe->pages)
		return -ENOMEM;

	nvbe->nr_pages = 0;
	while (num_pages--) {
		nvbe->pages[nvbe->nr_pages] =
			pci_map_page(dev->pdev, pages[nvbe->nr_pages], 0,
				     PAGE_SIZE, PCI_DMA_BIDIRECTIONAL);
		if (pci_dma_mapping_error(dev->pdev,
					  nvbe->pages[nvbe->nr_pages])) {
			be->func->clear(be);
			return -EFAULT;
		}

		nvbe->nr_pages++;
	}

	return 0;
}

static void
nouveau_sgdma_clear(struct ttm_backend *be)
{
	struct nouveau_sgdma_be *nvbe = (struct nouveau_sgdma_be *)be;
	struct drm_device *dev;

	if (nvbe && nvbe->pages) {
		dev = nvbe->dev;
		NV_DEBUG(dev, "\n");

		if (nvbe->bound)
			be->func->unbind(be);

		while (nvbe->nr_pages--) {
			pci_unmap_page(dev->pdev, nvbe->pages[nvbe->nr_pages],
				       PAGE_SIZE, PCI_DMA_BIDIRECTIONAL);
		}
		kfree(nvbe->pages);
		nvbe->pages = NULL;
		nvbe->nr_pages = 0;
	}
}

static int
nouveau_sgdma_bind(struct ttm_backend *be, struct ttm_mem_reg *mem)
{
	struct nouveau_sgdma_be *nvbe = (struct nouveau_sgdma_be *)be;
	struct drm_device *dev = nvbe->dev;
	struct drm_nouveau_private *dev_priv = dev->dev_private;
	struct nouveau_gpuobj *gpuobj = dev_priv->gart_info.sg_ctxdma;
	unsigned i, j, pte;

	NV_DEBUG(dev, "pg=0x%lx\n", mem->start);

	nvbe->offset = mem->start << PAGE_SHIFT;
	pte = (nvbe->offset >> NV_CTXDMA_PAGE_SHIFT) + 2;
	for (i = 0; i < nvbe->nr_pages; i++) {
		dma_addr_t dma_offset = nvbe->pages[i];
		uint32_t offset_l = lower_32_bits(dma_offset);

		for (j = 0; j < PAGE_SIZE / NV_CTXDMA_PAGE_SIZE; j++, pte++) {
			nv_wo32(gpuobj, (pte * 4) + 0, offset_l | 3);
			dma_offset += NV_CTXDMA_PAGE_SIZE;
		}
	}

	nvbe->bound = true;
	return 0;
}

static int
nouveau_sgdma_unbind(struct ttm_backend *be)
{
	struct nouveau_sgdma_be *nvbe = (struct nouveau_sgdma_be *)be;
	struct drm_device *dev = nvbe->dev;
	struct drm_nouveau_private *dev_priv = dev->dev_private;
	struct nouveau_gpuobj *gpuobj = dev_priv->gart_info.sg_ctxdma;
	unsigned i, j, pte;

	NV_DEBUG(dev, "\n");

	if (!nvbe->bound)
		return 0;

	pte = (nvbe->offset >> NV_CTXDMA_PAGE_SHIFT) + 2;
	for (i = 0; i < nvbe->nr_pages; i++) {
		for (j = 0; j < PAGE_SIZE / NV_CTXDMA_PAGE_SIZE; j++, pte++)
			nv_wo32(gpuobj, (pte * 4) + 0, 0x00000000);
	}

	nvbe->bound = false;
	return 0;
}

static void
nouveau_sgdma_destroy(struct ttm_backend *be)
{
	struct nouveau_sgdma_be *nvbe = (struct nouveau_sgdma_be *)be;

	if (be) {
		NV_DEBUG(nvbe->dev, "\n");

		if (nvbe) {
			if (nvbe->pages)
				be->func->clear(be);
			kfree(nvbe);
		}
	}
}

static int
nv50_sgdma_bind(struct ttm_backend *be, struct ttm_mem_reg *mem)
{
	struct nouveau_sgdma_be *nvbe = (struct nouveau_sgdma_be *)be;
	struct drm_nouveau_private *dev_priv = nvbe->dev->dev_private;

	nvbe->offset = mem->start << PAGE_SHIFT;

	nouveau_vm_map_sg(&dev_priv->gart_info.vma, nvbe->offset,
			  nvbe->nr_pages << PAGE_SHIFT, nvbe->pages);
	nvbe->bound = true;
	return 0;
}

static int
nv50_sgdma_unbind(struct ttm_backend *be)
{
	struct nouveau_sgdma_be *nvbe = (struct nouveau_sgdma_be *)be;
	struct drm_nouveau_private *dev_priv = nvbe->dev->dev_private;

	if (!nvbe->bound)
		return 0;

	nouveau_vm_unmap_at(&dev_priv->gart_info.vma, nvbe->offset,
			    nvbe->nr_pages << PAGE_SHIFT);
	nvbe->bound = false;
	return 0;
}

static struct ttm_backend_func nouveau_sgdma_backend = {
	.populate		= nouveau_sgdma_populate,
	.clear			= nouveau_sgdma_clear,
	.bind			= nouveau_sgdma_bind,
	.unbind			= nouveau_sgdma_unbind,
	.destroy		= nouveau_sgdma_destroy
};

static struct ttm_backend_func nv50_sgdma_backend = {
	.populate		= nouveau_sgdma_populate,
	.clear			= nouveau_sgdma_clear,
	.bind			= nv50_sgdma_bind,
	.unbind			= nv50_sgdma_unbind,
	.destroy		= nouveau_sgdma_destroy
};

struct ttm_backend *
nouveau_sgdma_init_ttm(struct drm_device *dev)
{
	struct drm_nouveau_private *dev_priv = dev->dev_private;
	struct nouveau_sgdma_be *nvbe;

	nvbe = kzalloc(sizeof(*nvbe), GFP_KERNEL);
	if (!nvbe)
		return NULL;

	nvbe->dev = dev;

	if (dev_priv->card_type < NV_50)
		nvbe->backend.func = &nouveau_sgdma_backend;
	else
		nvbe->backend.func = &nv50_sgdma_backend;
	return &nvbe->backend;
}

int
nouveau_sgdma_init(struct drm_device *dev)
{
	struct drm_nouveau_private *dev_priv = dev->dev_private;
	struct nouveau_gpuobj *gpuobj = NULL;
	uint32_t aper_size, obj_size;
	int i, ret;

	if (dev_priv->card_type < NV_50) {
		if(dev_priv->ramin_rsvd_vram < 2 * 1024 * 1024)
			aper_size = 64 * 1024 * 1024;
		else
			aper_size = 512 * 1024 * 1024;

		obj_size  = (aper_size >> NV_CTXDMA_PAGE_SHIFT) * 4;
		obj_size += 8; /* ctxdma header */

		ret = nouveau_gpuobj_new(dev, NULL, obj_size, 16,
					      NVOBJ_FLAG_ZERO_ALLOC |
					      NVOBJ_FLAG_ZERO_FREE, &gpuobj);
		if (ret) {
			NV_ERROR(dev, "Error creating sgdma object: %d\n", ret);
			return ret;
		}

		nv_wo32(gpuobj, 0, NV_CLASS_DMA_IN_MEMORY |
				   (1 << 12) /* PT present */ |
				   (0 << 13) /* PT *not* linear */ |
				   (0 << 14) /* RW */ |
				   (2 << 16) /* PCI */);
		nv_wo32(gpuobj, 4, aper_size - 1);
		for (i = 2; i < 2 + (aper_size >> 12); i++)
			nv_wo32(gpuobj, i * 4, 0x00000000);

		dev_priv->gart_info.sg_ctxdma = gpuobj;
		dev_priv->gart_info.aper_base = 0;
		dev_priv->gart_info.aper_size = aper_size;
	} else
	if (dev_priv->chan_vm) {
		ret = nouveau_vm_get(dev_priv->chan_vm, 512 * 1024 * 1024,
				     12, NV_MEM_ACCESS_RW,
				     &dev_priv->gart_info.vma);
		if (ret)
			return ret;

		dev_priv->gart_info.aper_base = dev_priv->gart_info.vma.offset;
		dev_priv->gart_info.aper_size = 512 * 1024 * 1024;
	}

	dev_priv->gart_info.type      = NOUVEAU_GART_SGDMA;
	return 0;
}

void
nouveau_sgdma_takedown(struct drm_device *dev)
{
	struct drm_nouveau_private *dev_priv = dev->dev_private;

	nouveau_gpuobj_ref(NULL, &dev_priv->gart_info.sg_ctxdma);
	nouveau_vm_put(&dev_priv->gart_info.vma);
}

uint32_t
nouveau_sgdma_get_physical(struct drm_device *dev, uint32_t offset)
{
	struct drm_nouveau_private *dev_priv = dev->dev_private;
	struct nouveau_gpuobj *gpuobj = dev_priv->gart_info.sg_ctxdma;
	int pte = (offset >> NV_CTXDMA_PAGE_SHIFT) + 2;

	BUG_ON(dev_priv->card_type >= NV_50);

	return (nv_ro32(gpuobj, 4 * pte) & ~NV_CTXDMA_PAGE_MASK) |
		(offset & NV_CTXDMA_PAGE_MASK);
}
