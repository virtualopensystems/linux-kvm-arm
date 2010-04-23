/****************************************************************************
 * Driver for Solarflare Solarstorm network controllers and boards
 * Copyright 2005-2006 Fen Systems Ltd.
 * Copyright 2005-2009 Solarflare Communications Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */

#include <linux/socket.h>
#include <linux/in.h>
#include <linux/slab.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <net/ip.h>
#include <net/checksum.h>
#include "net_driver.h"
#include "efx.h"
#include "nic.h"
#include "selftest.h"
#include "workarounds.h"

/* Number of RX descriptors pushed at once. */
#define EFX_RX_BATCH  8

/* Size of buffer allocated for skb header area. */
#define EFX_SKB_HEADERS  64u

/*
 * rx_alloc_method - RX buffer allocation method
 *
 * This driver supports two methods for allocating and using RX buffers:
 * each RX buffer may be backed by an skb or by an order-n page.
 *
 * When LRO is in use then the second method has a lower overhead,
 * since we don't have to allocate then free skbs on reassembled frames.
 *
 * Values:
 *   - RX_ALLOC_METHOD_AUTO = 0
 *   - RX_ALLOC_METHOD_SKB  = 1
 *   - RX_ALLOC_METHOD_PAGE = 2
 *
 * The heuristic for %RX_ALLOC_METHOD_AUTO is a simple hysteresis count
 * controlled by the parameters below.
 *
 *   - Since pushing and popping descriptors are separated by the rx_queue
 *     size, so the watermarks should be ~rxd_size.
 *   - The performance win by using page-based allocation for LRO is less
 *     than the performance hit of using page-based allocation of non-LRO,
 *     so the watermarks should reflect this.
 *
 * Per channel we maintain a single variable, updated by each channel:
 *
 *   rx_alloc_level += (lro_performed ? RX_ALLOC_FACTOR_LRO :
 *                      RX_ALLOC_FACTOR_SKB)
 * Per NAPI poll interval, we constrain rx_alloc_level to 0..MAX (which
 * limits the hysteresis), and update the allocation strategy:
 *
 *   rx_alloc_method = (rx_alloc_level > RX_ALLOC_LEVEL_LRO ?
 *                      RX_ALLOC_METHOD_PAGE : RX_ALLOC_METHOD_SKB)
 */
static int rx_alloc_method = RX_ALLOC_METHOD_AUTO;

#define RX_ALLOC_LEVEL_LRO 0x2000
#define RX_ALLOC_LEVEL_MAX 0x3000
#define RX_ALLOC_FACTOR_LRO 1
#define RX_ALLOC_FACTOR_SKB (-2)

/* This is the percentage fill level below which new RX descriptors
 * will be added to the RX descriptor ring.
 */
static unsigned int rx_refill_threshold = 90;

/* This is the percentage fill level to which an RX queue will be refilled
 * when the "RX refill threshold" is reached.
 */
static unsigned int rx_refill_limit = 95;

/*
 * RX maximum head room required.
 *
 * This must be at least 1 to prevent overflow and at least 2 to allow
 * pipelined receives.
 */
#define EFX_RXD_HEAD_ROOM 2

static inline unsigned int efx_rx_buf_offset(struct efx_rx_buffer *buf)
{
	/* Offset is always within one page, so we don't need to consider
	 * the page order.
	 */
	return (__force unsigned long) buf->data & (PAGE_SIZE - 1);
}
static inline unsigned int efx_rx_buf_size(struct efx_nic *efx)
{
	return PAGE_SIZE << efx->rx_buffer_order;
}


/**
 * efx_init_rx_buffer_skb - create new RX buffer using skb-based allocation
 *
 * @rx_queue:		Efx RX queue
 * @rx_buf:		RX buffer structure to populate
 *
 * This allocates memory for a new receive buffer, maps it for DMA,
 * and populates a struct efx_rx_buffer with the relevant
 * information.  Return a negative error code or 0 on success.
 */
static int efx_init_rx_buffer_skb(struct efx_rx_queue *rx_queue,
				  struct efx_rx_buffer *rx_buf)
{
	struct efx_nic *efx = rx_queue->efx;
	struct net_device *net_dev = efx->net_dev;
	int skb_len = efx->rx_buffer_len;

	rx_buf->skb = netdev_alloc_skb(net_dev, skb_len);
	if (unlikely(!rx_buf->skb))
		return -ENOMEM;

	/* Adjust the SKB for padding and checksum */
	skb_reserve(rx_buf->skb, NET_IP_ALIGN);
	rx_buf->len = skb_len - NET_IP_ALIGN;
	rx_buf->data = (char *)rx_buf->skb->data;
	rx_buf->skb->ip_summed = CHECKSUM_UNNECESSARY;

	rx_buf->dma_addr = pci_map_single(efx->pci_dev,
					  rx_buf->data, rx_buf->len,
					  PCI_DMA_FROMDEVICE);

	if (unlikely(pci_dma_mapping_error(efx->pci_dev, rx_buf->dma_addr))) {
		dev_kfree_skb_any(rx_buf->skb);
		rx_buf->skb = NULL;
		return -EIO;
	}

	return 0;
}

/**
 * efx_init_rx_buffer_page - create new RX buffer using page-based allocation
 *
 * @rx_queue:		Efx RX queue
 * @rx_buf:		RX buffer structure to populate
 *
 * This allocates memory for a new receive buffer, maps it for DMA,
 * and populates a struct efx_rx_buffer with the relevant
 * information.  Return a negative error code or 0 on success.
 */
static int efx_init_rx_buffer_page(struct efx_rx_queue *rx_queue,
				   struct efx_rx_buffer *rx_buf)
{
	struct efx_nic *efx = rx_queue->efx;
	int bytes, space, offset;

	bytes = efx->rx_buffer_len - EFX_PAGE_IP_ALIGN;

	/* If there is space left in the previously allocated page,
	 * then use it. Otherwise allocate a new one */
	rx_buf->page = rx_queue->buf_page;
	if (rx_buf->page == NULL) {
		dma_addr_t dma_addr;

		rx_buf->page = alloc_pages(__GFP_COLD | __GFP_COMP | GFP_ATOMIC,
					   efx->rx_buffer_order);
		if (unlikely(rx_buf->page == NULL))
			return -ENOMEM;

		dma_addr = pci_map_page(efx->pci_dev, rx_buf->page,
					0, efx_rx_buf_size(efx),
					PCI_DMA_FROMDEVICE);

		if (unlikely(pci_dma_mapping_error(efx->pci_dev, dma_addr))) {
			__free_pages(rx_buf->page, efx->rx_buffer_order);
			rx_buf->page = NULL;
			return -EIO;
		}

		rx_queue->buf_page = rx_buf->page;
		rx_queue->buf_dma_addr = dma_addr;
		rx_queue->buf_data = (page_address(rx_buf->page) +
				      EFX_PAGE_IP_ALIGN);
	}

	rx_buf->len = bytes;
	rx_buf->data = rx_queue->buf_data;
	offset = efx_rx_buf_offset(rx_buf);
	rx_buf->dma_addr = rx_queue->buf_dma_addr + offset;

	/* Try to pack multiple buffers per page */
	if (efx->rx_buffer_order == 0) {
		/* The next buffer starts on the next 512 byte boundary */
		rx_queue->buf_data += ((bytes + 0x1ff) & ~0x1ff);
		offset += ((bytes + 0x1ff) & ~0x1ff);

		space = efx_rx_buf_size(efx) - offset;
		if (space >= bytes) {
			/* Refs dropped on kernel releasing each skb */
			get_page(rx_queue->buf_page);
			goto out;
		}
	}

	/* This is the final RX buffer for this page, so mark it for
	 * unmapping */
	rx_queue->buf_page = NULL;
	rx_buf->unmap_addr = rx_queue->buf_dma_addr;

 out:
	return 0;
}

/* This allocates memory for a new receive buffer, maps it for DMA,
 * and populates a struct efx_rx_buffer with the relevant
 * information.
 */
static int efx_init_rx_buffer(struct efx_rx_queue *rx_queue,
			      struct efx_rx_buffer *new_rx_buf)
{
	int rc = 0;

	if (rx_queue->channel->rx_alloc_push_pages) {
		new_rx_buf->skb = NULL;
		rc = efx_init_rx_buffer_page(rx_queue, new_rx_buf);
		rx_queue->alloc_page_count++;
	} else {
		new_rx_buf->page = NULL;
		rc = efx_init_rx_buffer_skb(rx_queue, new_rx_buf);
		rx_queue->alloc_skb_count++;
	}

	if (unlikely(rc < 0))
		EFX_LOG_RL(rx_queue->efx, "%s RXQ[%d] =%d\n", __func__,
			   rx_queue->queue, rc);
	return rc;
}

static void efx_unmap_rx_buffer(struct efx_nic *efx,
				struct efx_rx_buffer *rx_buf)
{
	if (rx_buf->page) {
		EFX_BUG_ON_PARANOID(rx_buf->skb);
		if (rx_buf->unmap_addr) {
			pci_unmap_page(efx->pci_dev, rx_buf->unmap_addr,
				       efx_rx_buf_size(efx),
				       PCI_DMA_FROMDEVICE);
			rx_buf->unmap_addr = 0;
		}
	} else if (likely(rx_buf->skb)) {
		pci_unmap_single(efx->pci_dev, rx_buf->dma_addr,
				 rx_buf->len, PCI_DMA_FROMDEVICE);
	}
}

static void efx_free_rx_buffer(struct efx_nic *efx,
			       struct efx_rx_buffer *rx_buf)
{
	if (rx_buf->page) {
		__free_pages(rx_buf->page, efx->rx_buffer_order);
		rx_buf->page = NULL;
	} else if (likely(rx_buf->skb)) {
		dev_kfree_skb_any(rx_buf->skb);
		rx_buf->skb = NULL;
	}
}

static void efx_fini_rx_buffer(struct efx_rx_queue *rx_queue,
			       struct efx_rx_buffer *rx_buf)
{
	efx_unmap_rx_buffer(rx_queue->efx, rx_buf);
	efx_free_rx_buffer(rx_queue->efx, rx_buf);
}

/**
 * efx_fast_push_rx_descriptors - push new RX descriptors quickly
 * @rx_queue:		RX descriptor queue
 * @retry:              Recheck the fill level
 * This will aim to fill the RX descriptor queue up to
 * @rx_queue->@fast_fill_limit. If there is insufficient atomic
 * memory to do so, the caller should retry.
 */
static int __efx_fast_push_rx_descriptors(struct efx_rx_queue *rx_queue,
					  int retry)
{
	struct efx_rx_buffer *rx_buf;
	unsigned fill_level, index;
	int i, space, rc = 0;

	/* Calculate current fill level.  Do this outside the lock,
	 * because most of the time we'll end up not wanting to do the
	 * fill anyway.
	 */
	fill_level = (rx_queue->added_count - rx_queue->removed_count);
	EFX_BUG_ON_PARANOID(fill_level > EFX_RXQ_SIZE);

	/* Don't fill if we don't need to */
	if (fill_level >= rx_queue->fast_fill_trigger)
		return 0;

	/* Record minimum fill level */
	if (unlikely(fill_level < rx_queue->min_fill)) {
		if (fill_level)
			rx_queue->min_fill = fill_level;
	}

	/* Acquire RX add lock.  If this lock is contended, then a fast
	 * fill must already be in progress (e.g. in the refill
	 * tasklet), so we don't need to do anything
	 */
	if (!spin_trylock_bh(&rx_queue->add_lock))
		return -1;

 retry:
	/* Recalculate current fill level now that we have the lock */
	fill_level = (rx_queue->added_count - rx_queue->removed_count);
	EFX_BUG_ON_PARANOID(fill_level > EFX_RXQ_SIZE);
	space = rx_queue->fast_fill_limit - fill_level;
	if (space < EFX_RX_BATCH)
		goto out_unlock;

	EFX_TRACE(rx_queue->efx, "RX queue %d fast-filling descriptor ring from"
		  " level %d to level %d using %s allocation\n",
		  rx_queue->queue, fill_level, rx_queue->fast_fill_limit,
		  rx_queue->channel->rx_alloc_push_pages ? "page" : "skb");

	do {
		for (i = 0; i < EFX_RX_BATCH; ++i) {
			index = rx_queue->added_count & EFX_RXQ_MASK;
			rx_buf = efx_rx_buffer(rx_queue, index);
			rc = efx_init_rx_buffer(rx_queue, rx_buf);
			if (unlikely(rc))
				goto out;
			++rx_queue->added_count;
		}
	} while ((space -= EFX_RX_BATCH) >= EFX_RX_BATCH);

	EFX_TRACE(rx_queue->efx, "RX queue %d fast-filled descriptor ring "
		  "to level %d\n", rx_queue->queue,
		  rx_queue->added_count - rx_queue->removed_count);

 out:
	/* Send write pointer to card. */
	efx_nic_notify_rx_desc(rx_queue);

	/* If the fast fill is running inside from the refill tasklet, then
	 * for SMP systems it may be running on a different CPU to
	 * RX event processing, which means that the fill level may now be
	 * out of date. */
	if (unlikely(retry && (rc == 0)))
		goto retry;

 out_unlock:
	spin_unlock_bh(&rx_queue->add_lock);

	return rc;
}

/**
 * efx_fast_push_rx_descriptors - push new RX descriptors quickly
 * @rx_queue:		RX descriptor queue
 *
 * This will aim to fill the RX descriptor queue up to
 * @rx_queue->@fast_fill_limit.  If there is insufficient memory to do so,
 * it will schedule a work item to immediately continue the fast fill
 */
void efx_fast_push_rx_descriptors(struct efx_rx_queue *rx_queue)
{
	int rc;

	rc = __efx_fast_push_rx_descriptors(rx_queue, 0);
	if (unlikely(rc)) {
		/* Schedule the work item to run immediately. The hope is
		 * that work is immediately pending to free some memory
		 * (e.g. an RX event or TX completion)
		 */
		efx_schedule_slow_fill(rx_queue, 0);
	}
}

void efx_rx_work(struct work_struct *data)
{
	struct efx_rx_queue *rx_queue;
	int rc;

	rx_queue = container_of(data, struct efx_rx_queue, work.work);

	if (unlikely(!rx_queue->channel->enabled))
		return;

	EFX_TRACE(rx_queue->efx, "RX queue %d worker thread executing on CPU "
		  "%d\n", rx_queue->queue, raw_smp_processor_id());

	++rx_queue->slow_fill_count;
	/* Push new RX descriptors, allowing at least 1 jiffy for
	 * the kernel to free some more memory. */
	rc = __efx_fast_push_rx_descriptors(rx_queue, 1);
	if (rc)
		efx_schedule_slow_fill(rx_queue, 1);
}

static void efx_rx_packet__check_len(struct efx_rx_queue *rx_queue,
				     struct efx_rx_buffer *rx_buf,
				     int len, bool *discard,
				     bool *leak_packet)
{
	struct efx_nic *efx = rx_queue->efx;
	unsigned max_len = rx_buf->len - efx->type->rx_buffer_padding;

	if (likely(len <= max_len))
		return;

	/* The packet must be discarded, but this is only a fatal error
	 * if the caller indicated it was
	 */
	*discard = true;

	if ((len > rx_buf->len) && EFX_WORKAROUND_8071(efx)) {
		EFX_ERR_RL(efx, " RX queue %d seriously overlength "
			   "RX event (0x%x > 0x%x+0x%x). Leaking\n",
			   rx_queue->queue, len, max_len,
			   efx->type->rx_buffer_padding);
		/* If this buffer was skb-allocated, then the meta
		 * data at the end of the skb will be trashed. So
		 * we have no choice but to leak the fragment.
		 */
		*leak_packet = (rx_buf->skb != NULL);
		efx_schedule_reset(efx, RESET_TYPE_RX_RECOVERY);
	} else {
		EFX_ERR_RL(efx, " RX queue %d overlength RX event "
			   "(0x%x > 0x%x)\n", rx_queue->queue, len, max_len);
	}

	rx_queue->channel->n_rx_overlength++;
}

/* Pass a received packet up through the generic LRO stack
 *
 * Handles driverlink veto, and passes the fragment up via
 * the appropriate LRO method
 */
static void efx_rx_packet_lro(struct efx_channel *channel,
			      struct efx_rx_buffer *rx_buf,
			      bool checksummed)
{
	struct napi_struct *napi = &channel->napi_str;
	gro_result_t gro_result;

	/* Pass the skb/page into the LRO engine */
	if (rx_buf->page) {
		struct page *page = rx_buf->page;
		struct sk_buff *skb;

		EFX_BUG_ON_PARANOID(rx_buf->skb);
		rx_buf->page = NULL;

		skb = napi_get_frags(napi);
		if (!skb) {
			put_page(page);
			return;
		}

		skb_shinfo(skb)->frags[0].page = page;
		skb_shinfo(skb)->frags[0].page_offset =
			efx_rx_buf_offset(rx_buf);
		skb_shinfo(skb)->frags[0].size = rx_buf->len;
		skb_shinfo(skb)->nr_frags = 1;

		skb->len = rx_buf->len;
		skb->data_len = rx_buf->len;
		skb->truesize += rx_buf->len;
		skb->ip_summed =
			checksummed ? CHECKSUM_UNNECESSARY : CHECKSUM_NONE;

		skb_record_rx_queue(skb, channel->channel);

		gro_result = napi_gro_frags(napi);
	} else {
		struct sk_buff *skb = rx_buf->skb;

		EFX_BUG_ON_PARANOID(!skb);
		EFX_BUG_ON_PARANOID(!checksummed);
		rx_buf->skb = NULL;

		gro_result = napi_gro_receive(napi, skb);
	}

	if (gro_result == GRO_NORMAL) {
		channel->rx_alloc_level += RX_ALLOC_FACTOR_SKB;
	} else if (gro_result != GRO_DROP) {
		channel->rx_alloc_level += RX_ALLOC_FACTOR_LRO;
		channel->irq_mod_score += 2;
	}
}

void efx_rx_packet(struct efx_rx_queue *rx_queue, unsigned int index,
		   unsigned int len, bool checksummed, bool discard)
{
	struct efx_nic *efx = rx_queue->efx;
	struct efx_rx_buffer *rx_buf;
	bool leak_packet = false;

	rx_buf = efx_rx_buffer(rx_queue, index);
	EFX_BUG_ON_PARANOID(!rx_buf->data);
	EFX_BUG_ON_PARANOID(rx_buf->skb && rx_buf->page);
	EFX_BUG_ON_PARANOID(!(rx_buf->skb || rx_buf->page));

	/* This allows the refill path to post another buffer.
	 * EFX_RXD_HEAD_ROOM ensures that the slot we are using
	 * isn't overwritten yet.
	 */
	rx_queue->removed_count++;

	/* Validate the length encoded in the event vs the descriptor pushed */
	efx_rx_packet__check_len(rx_queue, rx_buf, len,
				 &discard, &leak_packet);

	EFX_TRACE(efx, "RX queue %d received id %x at %llx+%x %s%s\n",
		  rx_queue->queue, index,
		  (unsigned long long)rx_buf->dma_addr, len,
		  (checksummed ? " [SUMMED]" : ""),
		  (discard ? " [DISCARD]" : ""));

	/* Discard packet, if instructed to do so */
	if (unlikely(discard)) {
		if (unlikely(leak_packet))
			rx_queue->channel->n_skbuff_leaks++;
		else
			/* We haven't called efx_unmap_rx_buffer yet,
			 * so fini the entire rx_buffer here */
			efx_fini_rx_buffer(rx_queue, rx_buf);
		return;
	}

	/* Release card resources - assumes all RX buffers consumed in-order
	 * per RX queue
	 */
	efx_unmap_rx_buffer(efx, rx_buf);

	/* Prefetch nice and early so data will (hopefully) be in cache by
	 * the time we look at it.
	 */
	prefetch(rx_buf->data);

	/* Pipeline receives so that we give time for packet headers to be
	 * prefetched into cache.
	 */
	rx_buf->len = len;
	if (rx_queue->channel->rx_pkt)
		__efx_rx_packet(rx_queue->channel,
				rx_queue->channel->rx_pkt,
				rx_queue->channel->rx_pkt_csummed);
	rx_queue->channel->rx_pkt = rx_buf;
	rx_queue->channel->rx_pkt_csummed = checksummed;
}

/* Handle a received packet.  Second half: Touches packet payload. */
void __efx_rx_packet(struct efx_channel *channel,
		     struct efx_rx_buffer *rx_buf, bool checksummed)
{
	struct efx_nic *efx = channel->efx;
	struct sk_buff *skb;

	/* If we're in loopback test, then pass the packet directly to the
	 * loopback layer, and free the rx_buf here
	 */
	if (unlikely(efx->loopback_selftest)) {
		efx_loopback_rx_packet(efx, rx_buf->data, rx_buf->len);
		efx_free_rx_buffer(efx, rx_buf);
		return;
	}

	if (rx_buf->skb) {
		prefetch(skb_shinfo(rx_buf->skb));

		skb_put(rx_buf->skb, rx_buf->len);

		/* Move past the ethernet header. rx_buf->data still points
		 * at the ethernet header */
		rx_buf->skb->protocol = eth_type_trans(rx_buf->skb,
						       efx->net_dev);

		skb_record_rx_queue(rx_buf->skb, channel->channel);
	}

	if (likely(checksummed || rx_buf->page)) {
		efx_rx_packet_lro(channel, rx_buf, checksummed);
		return;
	}

	/* We now own the SKB */
	skb = rx_buf->skb;
	rx_buf->skb = NULL;
	EFX_BUG_ON_PARANOID(!skb);

	/* Set the SKB flags */
	skb->ip_summed = CHECKSUM_NONE;

	/* Pass the packet up */
	netif_receive_skb(skb);

	/* Update allocation strategy method */
	channel->rx_alloc_level += RX_ALLOC_FACTOR_SKB;
}

void efx_rx_strategy(struct efx_channel *channel)
{
	enum efx_rx_alloc_method method = rx_alloc_method;

	/* Only makes sense to use page based allocation if LRO is enabled */
	if (!(channel->efx->net_dev->features & NETIF_F_GRO)) {
		method = RX_ALLOC_METHOD_SKB;
	} else if (method == RX_ALLOC_METHOD_AUTO) {
		/* Constrain the rx_alloc_level */
		if (channel->rx_alloc_level < 0)
			channel->rx_alloc_level = 0;
		else if (channel->rx_alloc_level > RX_ALLOC_LEVEL_MAX)
			channel->rx_alloc_level = RX_ALLOC_LEVEL_MAX;

		/* Decide on the allocation method */
		method = ((channel->rx_alloc_level > RX_ALLOC_LEVEL_LRO) ?
			  RX_ALLOC_METHOD_PAGE : RX_ALLOC_METHOD_SKB);
	}

	/* Push the option */
	channel->rx_alloc_push_pages = (method == RX_ALLOC_METHOD_PAGE);
}

int efx_probe_rx_queue(struct efx_rx_queue *rx_queue)
{
	struct efx_nic *efx = rx_queue->efx;
	unsigned int rxq_size;
	int rc;

	EFX_LOG(efx, "creating RX queue %d\n", rx_queue->queue);

	/* Allocate RX buffers */
	rxq_size = EFX_RXQ_SIZE * sizeof(*rx_queue->buffer);
	rx_queue->buffer = kzalloc(rxq_size, GFP_KERNEL);
	if (!rx_queue->buffer)
		return -ENOMEM;

	rc = efx_nic_probe_rx(rx_queue);
	if (rc) {
		kfree(rx_queue->buffer);
		rx_queue->buffer = NULL;
	}
	return rc;
}

void efx_init_rx_queue(struct efx_rx_queue *rx_queue)
{
	unsigned int max_fill, trigger, limit;

	EFX_LOG(rx_queue->efx, "initialising RX queue %d\n", rx_queue->queue);

	/* Initialise ptr fields */
	rx_queue->added_count = 0;
	rx_queue->notified_count = 0;
	rx_queue->removed_count = 0;
	rx_queue->min_fill = -1U;
	rx_queue->min_overfill = -1U;

	/* Initialise limit fields */
	max_fill = EFX_RXQ_SIZE - EFX_RXD_HEAD_ROOM;
	trigger = max_fill * min(rx_refill_threshold, 100U) / 100U;
	limit = max_fill * min(rx_refill_limit, 100U) / 100U;

	rx_queue->max_fill = max_fill;
	rx_queue->fast_fill_trigger = trigger;
	rx_queue->fast_fill_limit = limit;

	/* Set up RX descriptor ring */
	efx_nic_init_rx(rx_queue);
}

void efx_fini_rx_queue(struct efx_rx_queue *rx_queue)
{
	int i;
	struct efx_rx_buffer *rx_buf;

	EFX_LOG(rx_queue->efx, "shutting down RX queue %d\n", rx_queue->queue);

	efx_nic_fini_rx(rx_queue);

	/* Release RX buffers NB start at index 0 not current HW ptr */
	if (rx_queue->buffer) {
		for (i = 0; i <= EFX_RXQ_MASK; i++) {
			rx_buf = efx_rx_buffer(rx_queue, i);
			efx_fini_rx_buffer(rx_queue, rx_buf);
		}
	}

	/* For a page that is part-way through splitting into RX buffers */
	if (rx_queue->buf_page != NULL) {
		pci_unmap_page(rx_queue->efx->pci_dev, rx_queue->buf_dma_addr,
			       efx_rx_buf_size(rx_queue->efx),
			       PCI_DMA_FROMDEVICE);
		__free_pages(rx_queue->buf_page,
			     rx_queue->efx->rx_buffer_order);
		rx_queue->buf_page = NULL;
	}
}

void efx_remove_rx_queue(struct efx_rx_queue *rx_queue)
{
	EFX_LOG(rx_queue->efx, "destroying RX queue %d\n", rx_queue->queue);

	efx_nic_remove_rx(rx_queue);

	kfree(rx_queue->buffer);
	rx_queue->buffer = NULL;
}


module_param(rx_alloc_method, int, 0644);
MODULE_PARM_DESC(rx_alloc_method, "Allocation method used for RX buffers");

module_param(rx_refill_threshold, uint, 0444);
MODULE_PARM_DESC(rx_refill_threshold,
		 "RX descriptor ring fast/slow fill threshold (%)");

