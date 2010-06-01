/*
 * Copyright (C) 2005-2007  Kristian Hoegsberg <krh@bitplanet.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#include <linux/bug.h>
#include <linux/completion.h>
#include <linux/crc-itu-t.h>
#include <linux/device.h>
#include <linux/errno.h>
#include <linux/firewire.h>
#include <linux/firewire-constants.h>
#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/kref.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>
#include <linux/workqueue.h>

#include <asm/atomic.h>
#include <asm/byteorder.h>

#include "core.h"

int fw_compute_block_crc(__be32 *block)
{
	int length;
	u16 crc;

	length = (be32_to_cpu(block[0]) >> 16) & 0xff;
	crc = crc_itu_t(0, (u8 *)&block[1], length * 4);
	*block |= cpu_to_be32(crc);

	return length;
}

static DEFINE_MUTEX(card_mutex);
static LIST_HEAD(card_list);

static LIST_HEAD(descriptor_list);
static int descriptor_count;

static __be32 tmp_config_rom[256];
/* ROM header, bus info block, root dir header, capabilities = 7 quadlets */
static size_t config_rom_length = 1 + 4 + 1 + 1;

#define BIB_CRC(v)		((v) <<  0)
#define BIB_CRC_LENGTH(v)	((v) << 16)
#define BIB_INFO_LENGTH(v)	((v) << 24)
#define BIB_BUS_NAME		0x31333934 /* "1394" */
#define BIB_LINK_SPEED(v)	((v) <<  0)
#define BIB_GENERATION(v)	((v) <<  4)
#define BIB_MAX_ROM(v)		((v) <<  8)
#define BIB_MAX_RECEIVE(v)	((v) << 12)
#define BIB_CYC_CLK_ACC(v)	((v) << 16)
#define BIB_PMC			((1) << 27)
#define BIB_BMC			((1) << 28)
#define BIB_ISC			((1) << 29)
#define BIB_CMC			((1) << 30)
#define BIB_IRMC		((1) << 31)
#define NODE_CAPABILITIES	0x0c0083c0 /* per IEEE 1394 clause 8.3.2.6.5.2 */

static void generate_config_rom(struct fw_card *card, __be32 *config_rom)
{
	struct fw_descriptor *desc;
	int i, j, k, length;

	/*
	 * Initialize contents of config rom buffer.  On the OHCI
	 * controller, block reads to the config rom accesses the host
	 * memory, but quadlet read access the hardware bus info block
	 * registers.  That's just crack, but it means we should make
	 * sure the contents of bus info block in host memory matches
	 * the version stored in the OHCI registers.
	 */

	config_rom[0] = cpu_to_be32(
		BIB_CRC_LENGTH(4) | BIB_INFO_LENGTH(4) | BIB_CRC(0));
	config_rom[1] = cpu_to_be32(BIB_BUS_NAME);
	config_rom[2] = cpu_to_be32(
		BIB_LINK_SPEED(card->link_speed) |
		BIB_GENERATION(card->config_rom_generation++ % 14 + 2) |
		BIB_MAX_ROM(2) |
		BIB_MAX_RECEIVE(card->max_receive) |
		BIB_BMC | BIB_ISC | BIB_CMC | BIB_IRMC);
	config_rom[3] = cpu_to_be32(card->guid >> 32);
	config_rom[4] = cpu_to_be32(card->guid);

	/* Generate root directory. */
	config_rom[6] = cpu_to_be32(NODE_CAPABILITIES);
	i = 7;
	j = 7 + descriptor_count;

	/* Generate root directory entries for descriptors. */
	list_for_each_entry (desc, &descriptor_list, link) {
		if (desc->immediate > 0)
			config_rom[i++] = cpu_to_be32(desc->immediate);
		config_rom[i] = cpu_to_be32(desc->key | (j - i));
		i++;
		j += desc->length;
	}

	/* Update root directory length. */
	config_rom[5] = cpu_to_be32((i - 5 - 1) << 16);

	/* End of root directory, now copy in descriptors. */
	list_for_each_entry (desc, &descriptor_list, link) {
		for (k = 0; k < desc->length; k++)
			config_rom[i + k] = cpu_to_be32(desc->data[k]);
		i += desc->length;
	}

	/* Calculate CRCs for all blocks in the config rom.  This
	 * assumes that CRC length and info length are identical for
	 * the bus info block, which is always the case for this
	 * implementation. */
	for (i = 0; i < j; i += length + 1)
		length = fw_compute_block_crc(config_rom + i);

	WARN_ON(j != config_rom_length);
}

static void update_config_roms(void)
{
	struct fw_card *card;

	list_for_each_entry (card, &card_list, link) {
		generate_config_rom(card, tmp_config_rom);
		card->driver->set_config_rom(card, tmp_config_rom,
					     config_rom_length);
	}
}

static size_t required_space(struct fw_descriptor *desc)
{
	/* descriptor + entry into root dir + optional immediate entry */
	return desc->length + 1 + (desc->immediate > 0 ? 1 : 0);
}

int fw_core_add_descriptor(struct fw_descriptor *desc)
{
	size_t i;
	int ret;

	/*
	 * Check descriptor is valid; the length of all blocks in the
	 * descriptor has to add up to exactly the length of the
	 * block.
	 */
	i = 0;
	while (i < desc->length)
		i += (desc->data[i] >> 16) + 1;

	if (i != desc->length)
		return -EINVAL;

	mutex_lock(&card_mutex);

	if (config_rom_length + required_space(desc) > 256) {
		ret = -EBUSY;
	} else {
		list_add_tail(&desc->link, &descriptor_list);
		config_rom_length += required_space(desc);
		descriptor_count++;
		if (desc->immediate > 0)
			descriptor_count++;
		update_config_roms();
		ret = 0;
	}

	mutex_unlock(&card_mutex);

	return ret;
}
EXPORT_SYMBOL(fw_core_add_descriptor);

void fw_core_remove_descriptor(struct fw_descriptor *desc)
{
	mutex_lock(&card_mutex);

	list_del(&desc->link);
	config_rom_length -= required_space(desc);
	descriptor_count--;
	if (desc->immediate > 0)
		descriptor_count--;
	update_config_roms();

	mutex_unlock(&card_mutex);
}
EXPORT_SYMBOL(fw_core_remove_descriptor);

static void allocate_broadcast_channel(struct fw_card *card, int generation)
{
	int channel, bandwidth = 0;

	fw_iso_resource_manage(card, generation, 1ULL << 31, &channel,
			       &bandwidth, true, card->bm_transaction_data);
	if (channel == 31) {
		card->broadcast_channel_allocated = true;
		device_for_each_child(card->device, (void *)(long)generation,
				      fw_device_set_broadcast_channel);
	}
}

static const char gap_count_table[] = {
	63, 5, 7, 8, 10, 13, 16, 18, 21, 24, 26, 29, 32, 35, 37, 40
};

void fw_schedule_bm_work(struct fw_card *card, unsigned long delay)
{
	fw_card_get(card);
	if (!schedule_delayed_work(&card->work, delay))
		fw_card_put(card);
}

static void fw_card_bm_work(struct work_struct *work)
{
	struct fw_card *card = container_of(work, struct fw_card, work.work);
	struct fw_device *root_device;
	struct fw_node *root_node;
	unsigned long flags;
	int root_id, new_root_id, irm_id, local_id;
	int gap_count, generation, grace, rcode;
	bool do_reset = false;
	bool root_device_is_running;
	bool root_device_is_cmc;

	spin_lock_irqsave(&card->lock, flags);

	if (card->local_node == NULL) {
		spin_unlock_irqrestore(&card->lock, flags);
		goto out_put_card;
	}

	generation = card->generation;
	root_node = card->root_node;
	fw_node_get(root_node);
	root_device = root_node->data;
	root_device_is_running = root_device &&
			atomic_read(&root_device->state) == FW_DEVICE_RUNNING;
	root_device_is_cmc = root_device && root_device->cmc;
	root_id  = root_node->node_id;
	irm_id   = card->irm_node->node_id;
	local_id = card->local_node->node_id;

	grace = time_after(jiffies, card->reset_jiffies + DIV_ROUND_UP(HZ, 8));

	if (is_next_generation(generation, card->bm_generation) ||
	    (card->bm_generation != generation && grace)) {
		/*
		 * This first step is to figure out who is IRM and
		 * then try to become bus manager.  If the IRM is not
		 * well defined (e.g. does not have an active link
		 * layer or does not responds to our lock request, we
		 * will have to do a little vigilante bus management.
		 * In that case, we do a goto into the gap count logic
		 * so that when we do the reset, we still optimize the
		 * gap count.  That could well save a reset in the
		 * next generation.
		 */

		if (!card->irm_node->link_on) {
			new_root_id = local_id;
			fw_notify("IRM has link off, making local node (%02x) root.\n",
				  new_root_id);
			goto pick_me;
		}

		card->bm_transaction_data[0] = cpu_to_be32(0x3f);
		card->bm_transaction_data[1] = cpu_to_be32(local_id);

		spin_unlock_irqrestore(&card->lock, flags);

		rcode = fw_run_transaction(card, TCODE_LOCK_COMPARE_SWAP,
				irm_id, generation, SCODE_100,
				CSR_REGISTER_BASE + CSR_BUS_MANAGER_ID,
				card->bm_transaction_data,
				sizeof(card->bm_transaction_data));

		if (rcode == RCODE_GENERATION)
			/* Another bus reset, BM work has been rescheduled. */
			goto out;

		if (rcode == RCODE_COMPLETE &&
		    card->bm_transaction_data[0] != cpu_to_be32(0x3f)) {

			/* Somebody else is BM.  Only act as IRM. */
			if (local_id == irm_id)
				allocate_broadcast_channel(card, generation);

			goto out;
		}

		spin_lock_irqsave(&card->lock, flags);

		if (rcode != RCODE_COMPLETE) {
			/*
			 * The lock request failed, maybe the IRM
			 * isn't really IRM capable after all. Let's
			 * do a bus reset and pick the local node as
			 * root, and thus, IRM.
			 */
			new_root_id = local_id;
			fw_notify("BM lock failed, making local node (%02x) root.\n",
				  new_root_id);
			goto pick_me;
		}
	} else if (card->bm_generation != generation) {
		/*
		 * We weren't BM in the last generation, and the last
		 * bus reset is less than 125ms ago.  Reschedule this job.
		 */
		spin_unlock_irqrestore(&card->lock, flags);
		fw_schedule_bm_work(card, DIV_ROUND_UP(HZ, 8));
		goto out;
	}

	/*
	 * We're bus manager for this generation, so next step is to
	 * make sure we have an active cycle master and do gap count
	 * optimization.
	 */
	card->bm_generation = generation;

	if (root_device == NULL) {
		/*
		 * Either link_on is false, or we failed to read the
		 * config rom.  In either case, pick another root.
		 */
		new_root_id = local_id;
	} else if (!root_device_is_running) {
		/*
		 * If we haven't probed this device yet, bail out now
		 * and let's try again once that's done.
		 */
		spin_unlock_irqrestore(&card->lock, flags);
		goto out;
	} else if (root_device_is_cmc) {
		/*
		 * FIXME: I suppose we should set the cmstr bit in the
		 * STATE_CLEAR register of this node, as described in
		 * 1394-1995, 8.4.2.6.  Also, send out a force root
		 * packet for this node.
		 */
		new_root_id = root_id;
	} else {
		/*
		 * Current root has an active link layer and we
		 * successfully read the config rom, but it's not
		 * cycle master capable.
		 */
		new_root_id = local_id;
	}

 pick_me:
	/*
	 * Pick a gap count from 1394a table E-1.  The table doesn't cover
	 * the typically much larger 1394b beta repeater delays though.
	 */
	if (!card->beta_repeaters_present &&
	    root_node->max_hops < ARRAY_SIZE(gap_count_table))
		gap_count = gap_count_table[root_node->max_hops];
	else
		gap_count = 63;

	/*
	 * Finally, figure out if we should do a reset or not.  If we have
	 * done less than 5 resets with the same physical topology and we
	 * have either a new root or a new gap count setting, let's do it.
	 */

	if (card->bm_retries++ < 5 &&
	    (card->gap_count != gap_count || new_root_id != root_id))
		do_reset = true;

	spin_unlock_irqrestore(&card->lock, flags);

	if (do_reset) {
		fw_notify("phy config: card %d, new root=%x, gap_count=%d\n",
			  card->index, new_root_id, gap_count);
		fw_send_phy_config(card, new_root_id, generation, gap_count);
		fw_core_initiate_bus_reset(card, 1);
		/* Will allocate broadcast channel after the reset. */
	} else {
		if (local_id == irm_id)
			allocate_broadcast_channel(card, generation);
	}

 out:
	fw_node_put(root_node);
 out_put_card:
	fw_card_put(card);
}

void fw_card_initialize(struct fw_card *card,
			const struct fw_card_driver *driver,
			struct device *device)
{
	static atomic_t index = ATOMIC_INIT(-1);

	card->index = atomic_inc_return(&index);
	card->driver = driver;
	card->device = device;
	card->current_tlabel = 0;
	card->tlabel_mask = 0;
	card->color = 0;
	card->broadcast_channel = BROADCAST_CHANNEL_INITIAL;

	kref_init(&card->kref);
	init_completion(&card->done);
	INIT_LIST_HEAD(&card->transaction_list);
	spin_lock_init(&card->lock);

	card->local_node = NULL;

	INIT_DELAYED_WORK(&card->work, fw_card_bm_work);
}
EXPORT_SYMBOL(fw_card_initialize);

int fw_card_add(struct fw_card *card,
		u32 max_receive, u32 link_speed, u64 guid)
{
	int ret;

	card->max_receive = max_receive;
	card->link_speed = link_speed;
	card->guid = guid;

	mutex_lock(&card_mutex);

	generate_config_rom(card, tmp_config_rom);
	ret = card->driver->enable(card, tmp_config_rom, config_rom_length);
	if (ret == 0)
		list_add_tail(&card->link, &card_list);

	mutex_unlock(&card_mutex);

	return ret;
}
EXPORT_SYMBOL(fw_card_add);


/*
 * The next few functions implement a dummy driver that is used once a card
 * driver shuts down an fw_card.  This allows the driver to cleanly unload,
 * as all IO to the card will be handled (and failed) by the dummy driver
 * instead of calling into the module.  Only functions for iso context
 * shutdown still need to be provided by the card driver.
 */

static int dummy_enable(struct fw_card *card,
			const __be32 *config_rom, size_t length)
{
	BUG();
	return -1;
}

static int dummy_update_phy_reg(struct fw_card *card, int address,
				int clear_bits, int set_bits)
{
	return -ENODEV;
}

static int dummy_set_config_rom(struct fw_card *card,
				const __be32 *config_rom, size_t length)
{
	/*
	 * We take the card out of card_list before setting the dummy
	 * driver, so this should never get called.
	 */
	BUG();
	return -1;
}

static void dummy_send_request(struct fw_card *card, struct fw_packet *packet)
{
	packet->callback(packet, card, -ENODEV);
}

static void dummy_send_response(struct fw_card *card, struct fw_packet *packet)
{
	packet->callback(packet, card, -ENODEV);
}

static int dummy_cancel_packet(struct fw_card *card, struct fw_packet *packet)
{
	return -ENOENT;
}

static int dummy_enable_phys_dma(struct fw_card *card,
				 int node_id, int generation)
{
	return -ENODEV;
}

static const struct fw_card_driver dummy_driver_template = {
	.enable          = dummy_enable,
	.update_phy_reg  = dummy_update_phy_reg,
	.set_config_rom  = dummy_set_config_rom,
	.send_request    = dummy_send_request,
	.cancel_packet   = dummy_cancel_packet,
	.send_response   = dummy_send_response,
	.enable_phys_dma = dummy_enable_phys_dma,
};

void fw_card_release(struct kref *kref)
{
	struct fw_card *card = container_of(kref, struct fw_card, kref);

	complete(&card->done);
}

void fw_core_remove_card(struct fw_card *card)
{
	struct fw_card_driver dummy_driver = dummy_driver_template;

	card->driver->update_phy_reg(card, 4,
				     PHY_LINK_ACTIVE | PHY_CONTENDER, 0);
	fw_core_initiate_bus_reset(card, 1);

	mutex_lock(&card_mutex);
	list_del_init(&card->link);
	mutex_unlock(&card_mutex);

	/* Switch off most of the card driver interface. */
	dummy_driver.free_iso_context	= card->driver->free_iso_context;
	dummy_driver.stop_iso		= card->driver->stop_iso;
	card->driver = &dummy_driver;

	fw_destroy_nodes(card);

	/* Wait for all users, especially device workqueue jobs, to finish. */
	fw_card_put(card);
	wait_for_completion(&card->done);

	WARN_ON(!list_empty(&card->transaction_list));
}
EXPORT_SYMBOL(fw_core_remove_card);

int fw_core_initiate_bus_reset(struct fw_card *card, int short_reset)
{
	int reg = short_reset ? 5 : 1;
	int bit = short_reset ? PHY_BUS_SHORT_RESET : PHY_BUS_RESET;

	return card->driver->update_phy_reg(card, reg, 0, bit);
}
EXPORT_SYMBOL(fw_core_initiate_bus_reset);
