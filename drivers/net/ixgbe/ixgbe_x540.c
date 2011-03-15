/*******************************************************************************

  Intel 10 Gigabit PCI Express Linux driver
  Copyright(c) 1999 - 2010 Intel Corporation.

  This program is free software; you can redistribute it and/or modify it
  under the terms and conditions of the GNU General Public License,
  version 2, as published by the Free Software Foundation.

  This program is distributed in the hope it will be useful, but WITHOUT
  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
  FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
  more details.

  You should have received a copy of the GNU General Public License along with
  this program; if not, write to the Free Software Foundation, Inc.,
  51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.

  The full GNU General Public License is included in this distribution in
  the file called "COPYING".

  Contact Information:
  e1000-devel Mailing List <e1000-devel@lists.sourceforge.net>
  Intel Corporation, 5200 N.E. Elam Young Parkway, Hillsboro, OR 97124-6497

*******************************************************************************/

#include <linux/pci.h>
#include <linux/delay.h>
#include <linux/sched.h>

#include "ixgbe.h"
#include "ixgbe_phy.h"
//#include "ixgbe_mbx.h"

#define IXGBE_X540_MAX_TX_QUEUES 128
#define IXGBE_X540_MAX_RX_QUEUES 128
#define IXGBE_X540_RAR_ENTRIES   128
#define IXGBE_X540_MC_TBL_SIZE   128
#define IXGBE_X540_VFT_TBL_SIZE  128

static s32 ixgbe_update_flash_X540(struct ixgbe_hw *hw);
static s32 ixgbe_poll_flash_update_done_X540(struct ixgbe_hw *hw);
static s32 ixgbe_acquire_swfw_sync_X540(struct ixgbe_hw *hw, u16 mask);
static void ixgbe_release_swfw_sync_X540(struct ixgbe_hw *hw, u16 mask);
static s32 ixgbe_get_swfw_sync_semaphore(struct ixgbe_hw *hw);
static void ixgbe_release_swfw_sync_semaphore(struct ixgbe_hw *hw);

static enum ixgbe_media_type ixgbe_get_media_type_X540(struct ixgbe_hw *hw)
{
	return ixgbe_media_type_copper;
}

static s32 ixgbe_get_invariants_X540(struct ixgbe_hw *hw)
{
	struct ixgbe_mac_info *mac = &hw->mac;

	/* Call PHY identify routine to get the phy type */
	ixgbe_identify_phy_generic(hw);

	mac->mcft_size = IXGBE_X540_MC_TBL_SIZE;
	mac->vft_size = IXGBE_X540_VFT_TBL_SIZE;
	mac->num_rar_entries = IXGBE_X540_RAR_ENTRIES;
	mac->max_rx_queues = IXGBE_X540_MAX_RX_QUEUES;
	mac->max_tx_queues = IXGBE_X540_MAX_TX_QUEUES;
	mac->max_msix_vectors = ixgbe_get_pcie_msix_count_generic(hw);

	return 0;
}

/**
 *  ixgbe_setup_mac_link_X540 - Set the auto advertised capabilitires
 *  @hw: pointer to hardware structure
 *  @speed: new link speed
 *  @autoneg: true if autonegotiation enabled
 *  @autoneg_wait_to_complete: true when waiting for completion is needed
 **/
static s32 ixgbe_setup_mac_link_X540(struct ixgbe_hw *hw,
                                     ixgbe_link_speed speed, bool autoneg,
                                     bool autoneg_wait_to_complete)
{
	return hw->phy.ops.setup_link_speed(hw, speed, autoneg,
	                                    autoneg_wait_to_complete);
}

/**
 *  ixgbe_reset_hw_X540 - Perform hardware reset
 *  @hw: pointer to hardware structure
 *
 *  Resets the hardware by resetting the transmit and receive units, masks
 *  and clears all interrupts, perform a PHY reset, and perform a link (MAC)
 *  reset.
 **/
static s32 ixgbe_reset_hw_X540(struct ixgbe_hw *hw)
{
	ixgbe_link_speed link_speed;
	s32 status = 0;
	u32 ctrl;
	u32 ctrl_ext;
	u32 reset_bit;
	u32 i;
	u32 autoc;
	u32 autoc2;
	bool link_up = false;

	/* Call adapter stop to disable tx/rx and clear interrupts */
	hw->mac.ops.stop_adapter(hw);

	/*
	 * Prevent the PCI-E bus from from hanging by disabling PCI-E master
	 * access and verify no pending requests before reset
	 */
	status = ixgbe_disable_pcie_master(hw);
	if (status != 0) {
		status = IXGBE_ERR_MASTER_REQUESTS_PENDING;
		hw_dbg(hw, "PCI-E Master disable polling has failed.\n");
	}

	/*
	 * Issue global reset to the MAC.  Needs to be SW reset if link is up.
	 * If link reset is used when link is up, it might reset the PHY when
	 * mng is using it.  If link is down or the flag to force full link
	 * reset is set, then perform link reset.
	 */
	if (hw->force_full_reset) {
		reset_bit = IXGBE_CTRL_LNK_RST;
	} else {
		hw->mac.ops.check_link(hw, &link_speed, &link_up, false);
		if (!link_up)
			reset_bit = IXGBE_CTRL_LNK_RST;
		else
			reset_bit = IXGBE_CTRL_RST;
	}

	ctrl = IXGBE_READ_REG(hw, IXGBE_CTRL);
	IXGBE_WRITE_REG(hw, IXGBE_CTRL, (ctrl | reset_bit));
	IXGBE_WRITE_FLUSH(hw);

	/* Poll for reset bit to self-clear indicating reset is complete */
	for (i = 0; i < 10; i++) {
		udelay(1);
		ctrl = IXGBE_READ_REG(hw, IXGBE_CTRL);
		if (!(ctrl & reset_bit))
			break;
	}
	if (ctrl & reset_bit) {
		status = IXGBE_ERR_RESET_FAILED;
		hw_dbg(hw, "Reset polling failed to complete.\n");
	}

	/* Clear PF Reset Done bit so PF/VF Mail Ops can work */
	ctrl_ext = IXGBE_READ_REG(hw, IXGBE_CTRL_EXT);
	ctrl_ext |= IXGBE_CTRL_EXT_PFRSTD;
	IXGBE_WRITE_REG(hw, IXGBE_CTRL_EXT, ctrl_ext);

	msleep(50);

	/* Set the Rx packet buffer size. */
	IXGBE_WRITE_REG(hw, IXGBE_RXPBSIZE(0), 384 << IXGBE_RXPBSIZE_SHIFT);

	/* Store the permanent mac address */
	hw->mac.ops.get_mac_addr(hw, hw->mac.perm_addr);

	/*
	 * Store the original AUTOC/AUTOC2 values if they have not been
	 * stored off yet.  Otherwise restore the stored original
	 * values since the reset operation sets back to defaults.
	 */
	autoc = IXGBE_READ_REG(hw, IXGBE_AUTOC);
	autoc2 = IXGBE_READ_REG(hw, IXGBE_AUTOC2);
	if (hw->mac.orig_link_settings_stored == false) {
		hw->mac.orig_autoc = autoc;
		hw->mac.orig_autoc2 = autoc2;
		hw->mac.orig_link_settings_stored = true;
	} else {
		if (autoc != hw->mac.orig_autoc)
			IXGBE_WRITE_REG(hw, IXGBE_AUTOC, (hw->mac.orig_autoc |
			                IXGBE_AUTOC_AN_RESTART));

		if ((autoc2 & IXGBE_AUTOC2_UPPER_MASK) !=
		    (hw->mac.orig_autoc2 & IXGBE_AUTOC2_UPPER_MASK)) {
			autoc2 &= ~IXGBE_AUTOC2_UPPER_MASK;
			autoc2 |= (hw->mac.orig_autoc2 &
			           IXGBE_AUTOC2_UPPER_MASK);
			IXGBE_WRITE_REG(hw, IXGBE_AUTOC2, autoc2);
		}
	}

	/*
	 * Store MAC address from RAR0, clear receive address registers, and
	 * clear the multicast table.  Also reset num_rar_entries to 128,
	 * since we modify this value when programming the SAN MAC address.
	 */
	hw->mac.num_rar_entries = 128;
	hw->mac.ops.init_rx_addrs(hw);

	/* Store the permanent mac address */
	hw->mac.ops.get_mac_addr(hw, hw->mac.perm_addr);

	/* Store the permanent SAN mac address */
	hw->mac.ops.get_san_mac_addr(hw, hw->mac.san_addr);

	/* Add the SAN MAC address to the RAR only if it's a valid address */
	if (ixgbe_validate_mac_addr(hw->mac.san_addr) == 0) {
		hw->mac.ops.set_rar(hw, hw->mac.num_rar_entries - 1,
		                    hw->mac.san_addr, 0, IXGBE_RAH_AV);

		/* Reserve the last RAR for the SAN MAC address */
		hw->mac.num_rar_entries--;
	}

	/* Store the alternative WWNN/WWPN prefix */
	hw->mac.ops.get_wwn_prefix(hw, &hw->mac.wwnn_prefix,
	                           &hw->mac.wwpn_prefix);

	return status;
}

/**
 *  ixgbe_get_supported_physical_layer_X540 - Returns physical layer type
 *  @hw: pointer to hardware structure
 *
 *  Determines physical layer capabilities of the current configuration.
 **/
static u32 ixgbe_get_supported_physical_layer_X540(struct ixgbe_hw *hw)
{
	u32 physical_layer = IXGBE_PHYSICAL_LAYER_UNKNOWN;
	u16 ext_ability = 0;

	hw->phy.ops.identify(hw);

	hw->phy.ops.read_reg(hw, MDIO_PMA_EXTABLE, MDIO_MMD_PMAPMD,
			     &ext_ability);
	if (ext_ability & MDIO_PMA_EXTABLE_10GBT)
		physical_layer |= IXGBE_PHYSICAL_LAYER_10GBASE_T;
	if (ext_ability & MDIO_PMA_EXTABLE_1000BT)
		physical_layer |= IXGBE_PHYSICAL_LAYER_1000BASE_T;
	if (ext_ability & MDIO_PMA_EXTABLE_100BTX)
		physical_layer |= IXGBE_PHYSICAL_LAYER_100BASE_TX;

	return physical_layer;
}

/**
 * ixgbe_init_eeprom_params_X540 - Initialize EEPROM params
 * @hw: pointer to hardware structure
 **/
static s32 ixgbe_init_eeprom_params_X540(struct ixgbe_hw *hw)
{
	struct ixgbe_eeprom_info *eeprom = &hw->eeprom;
	u32 eec;
	u16 eeprom_size;

	if (eeprom->type == ixgbe_eeprom_uninitialized) {
		eeprom->semaphore_delay = 10;
		eeprom->type = ixgbe_flash;

		eec = IXGBE_READ_REG(hw, IXGBE_EEC);
		eeprom_size = (u16)((eec & IXGBE_EEC_SIZE) >>
		                    IXGBE_EEC_SIZE_SHIFT);
		eeprom->word_size = 1 << (eeprom_size +
		                          IXGBE_EEPROM_WORD_SIZE_SHIFT);

		hw_dbg(hw, "Eeprom params: type = %d, size = %d\n",
		        eeprom->type, eeprom->word_size);
	}

	return 0;
}

/**
 * ixgbe_read_eerd_X540 - Read EEPROM word using EERD
 * @hw: pointer to hardware structure
 * @offset: offset of word in the EEPROM to read
 * @data: word read from the EERPOM
 **/
static s32 ixgbe_read_eerd_X540(struct ixgbe_hw *hw, u16 offset, u16 *data)
{
	s32 status;

	if (ixgbe_acquire_swfw_sync_X540(hw, IXGBE_GSSR_EEP_SM) == 0)
		status = ixgbe_read_eerd_generic(hw, offset, data);
	else
		status = IXGBE_ERR_SWFW_SYNC;

	ixgbe_release_swfw_sync_X540(hw, IXGBE_GSSR_EEP_SM);
	return status;
}

/**
 * ixgbe_write_eewr_X540 - Write EEPROM word using EEWR
 * @hw: pointer to hardware structure
 * @offset: offset of  word in the EEPROM to write
 * @data: word write to the EEPROM
 *
 * Write a 16 bit word to the EEPROM using the EEWR register.
 **/
static s32 ixgbe_write_eewr_X540(struct ixgbe_hw *hw, u16 offset, u16 data)
{
	u32 eewr;
	s32 status;

	hw->eeprom.ops.init_params(hw);

	if (offset >= hw->eeprom.word_size) {
		status = IXGBE_ERR_EEPROM;
		goto out;
	}

	eewr = (offset << IXGBE_EEPROM_RW_ADDR_SHIFT) |
	       (data << IXGBE_EEPROM_RW_REG_DATA) |
	       IXGBE_EEPROM_RW_REG_START;

	if (ixgbe_acquire_swfw_sync_X540(hw, IXGBE_GSSR_EEP_SM) == 0) {
		status = ixgbe_poll_eerd_eewr_done(hw, IXGBE_NVM_POLL_WRITE);
		if (status != 0) {
			hw_dbg(hw, "Eeprom write EEWR timed out\n");
			goto out;
		}

		IXGBE_WRITE_REG(hw, IXGBE_EEWR, eewr);

		status = ixgbe_poll_eerd_eewr_done(hw, IXGBE_NVM_POLL_WRITE);
		if (status != 0) {
			hw_dbg(hw, "Eeprom write EEWR timed out\n");
			goto out;
		}
	} else {
		status = IXGBE_ERR_SWFW_SYNC;
	}

out:
	ixgbe_release_swfw_sync_X540(hw, IXGBE_GSSR_EEP_SM);
	return status;
}

/**
 * ixgbe_calc_eeprom_checksum_X540 - Calculates and returns the checksum
 * @hw: pointer to hardware structure
 **/
static u16 ixgbe_calc_eeprom_checksum_X540(struct ixgbe_hw *hw)
{
	u16 i;
	u16 j;
	u16 checksum = 0;
	u16 length = 0;
	u16 pointer = 0;
	u16 word = 0;

	/* Include 0x0-0x3F in the checksum */
	for (i = 0; i < IXGBE_EEPROM_CHECKSUM; i++) {
		if (hw->eeprom.ops.read(hw, i, &word) != 0) {
			hw_dbg(hw, "EEPROM read failed\n");
			break;
		}
		checksum += word;
	}

	/*
	 * Include all data from pointers 0x3, 0x6-0xE.  This excludes the
	 * FW, PHY module, and PCIe Expansion/Option ROM pointers.
	 */
	for (i = IXGBE_PCIE_ANALOG_PTR; i < IXGBE_FW_PTR; i++) {
		if (i == IXGBE_PHY_PTR || i == IXGBE_OPTION_ROM_PTR)
			continue;

		if (hw->eeprom.ops.read(hw, i, &pointer) != 0) {
			hw_dbg(hw, "EEPROM read failed\n");
			break;
		}

		/* Skip pointer section if the pointer is invalid. */
		if (pointer == 0xFFFF || pointer == 0 ||
		    pointer >= hw->eeprom.word_size)
			continue;

		if (hw->eeprom.ops.read(hw, pointer, &length) != 0) {
			hw_dbg(hw, "EEPROM read failed\n");
			break;
		}

		/* Skip pointer section if length is invalid. */
		if (length == 0xFFFF || length == 0 ||
		    (pointer + length) >= hw->eeprom.word_size)
			continue;

		for (j = pointer+1; j <= pointer+length; j++) {
			if (hw->eeprom.ops.read(hw, j, &word) != 0) {
				hw_dbg(hw, "EEPROM read failed\n");
				break;
			}
			checksum += word;
		}
	}

	checksum = (u16)IXGBE_EEPROM_SUM - checksum;

	return checksum;
}

/**
 * ixgbe_update_eeprom_checksum_X540 - Updates the EEPROM checksum and flash
 * @hw: pointer to hardware structure
 *
 * After writing EEPROM to shadow RAM using EEWR register, software calculates
 * checksum and updates the EEPROM and instructs the hardware to update
 * the flash.
 **/
static s32 ixgbe_update_eeprom_checksum_X540(struct ixgbe_hw *hw)
{
	s32 status;

	status = ixgbe_update_eeprom_checksum_generic(hw);

	if (status)
		status = ixgbe_update_flash_X540(hw);

	return status;
}

/**
 * ixgbe_update_flash_X540 - Instruct HW to copy EEPROM to Flash device
 * @hw: pointer to hardware structure
 *
 * Set FLUP (bit 23) of the EEC register to instruct Hardware to copy
 * EEPROM from shadow RAM to the flash device.
 **/
static s32 ixgbe_update_flash_X540(struct ixgbe_hw *hw)
{
	u32 flup;
	s32 status = IXGBE_ERR_EEPROM;

	status = ixgbe_poll_flash_update_done_X540(hw);
	if (status == IXGBE_ERR_EEPROM) {
		hw_dbg(hw, "Flash update time out\n");
		goto out;
	}

	flup = IXGBE_READ_REG(hw, IXGBE_EEC) | IXGBE_EEC_FLUP;
	IXGBE_WRITE_REG(hw, IXGBE_EEC, flup);

	status = ixgbe_poll_flash_update_done_X540(hw);
	if (status)
		hw_dbg(hw, "Flash update complete\n");
	else
		hw_dbg(hw, "Flash update time out\n");

	if (hw->revision_id == 0) {
		flup = IXGBE_READ_REG(hw, IXGBE_EEC);

		if (flup & IXGBE_EEC_SEC1VAL) {
			flup |= IXGBE_EEC_FLUP;
			IXGBE_WRITE_REG(hw, IXGBE_EEC, flup);
		}

		status = ixgbe_poll_flash_update_done_X540(hw);
		if (status)
			hw_dbg(hw, "Flash update complete\n");
		else
			hw_dbg(hw, "Flash update time out\n");

	}
out:
	return status;
}

/**
 * ixgbe_poll_flash_update_done_X540 - Poll flash update status
 * @hw: pointer to hardware structure
 *
 * Polls the FLUDONE (bit 26) of the EEC Register to determine when the
 * flash update is done.
 **/
static s32 ixgbe_poll_flash_update_done_X540(struct ixgbe_hw *hw)
{
	u32 i;
	u32 reg;
	s32 status = IXGBE_ERR_EEPROM;

	for (i = 0; i < IXGBE_FLUDONE_ATTEMPTS; i++) {
		reg = IXGBE_READ_REG(hw, IXGBE_EEC);
		if (reg & IXGBE_EEC_FLUDONE) {
			status = 0;
			break;
		}
		udelay(5);
	}
	return status;
}

/**
 * ixgbe_acquire_swfw_sync_X540 - Acquire SWFW semaphore
 * @hw: pointer to hardware structure
 * @mask: Mask to specify which semaphore to acquire
 *
 * Acquires the SWFW semaphore thought the SW_FW_SYNC register for
 * the specified function (CSR, PHY0, PHY1, NVM, Flash)
 **/
static s32 ixgbe_acquire_swfw_sync_X540(struct ixgbe_hw *hw, u16 mask)
{
	u32 swfw_sync;
	u32 swmask = mask;
	u32 fwmask = mask << 5;
	u32 hwmask = 0;
	u32 timeout = 200;
	u32 i;

	if (swmask == IXGBE_GSSR_EEP_SM)
		hwmask = IXGBE_GSSR_FLASH_SM;

	for (i = 0; i < timeout; i++) {
		/*
		 * SW NVM semaphore bit is used for access to all
		 * SW_FW_SYNC bits (not just NVM)
		 */
		if (ixgbe_get_swfw_sync_semaphore(hw))
			return IXGBE_ERR_SWFW_SYNC;

		swfw_sync = IXGBE_READ_REG(hw, IXGBE_SWFW_SYNC);
		if (!(swfw_sync & (fwmask | swmask | hwmask))) {
			swfw_sync |= swmask;
			IXGBE_WRITE_REG(hw, IXGBE_SWFW_SYNC, swfw_sync);
			ixgbe_release_swfw_sync_semaphore(hw);
			break;
		} else {
			/*
			 * Firmware currently using resource (fwmask),
			 * hardware currently using resource (hwmask),
			 * or other software thread currently using
			 * resource (swmask)
			 */
			ixgbe_release_swfw_sync_semaphore(hw);
			msleep(5);
		}
	}

	/*
	 * If the resource is not released by the FW/HW the SW can assume that
	 * the FW/HW malfunctions. In that case the SW should sets the
	 * SW bit(s) of the requested resource(s) while ignoring the
	 * corresponding FW/HW bits in the SW_FW_SYNC register.
	 */
	if (i >= timeout) {
		swfw_sync = IXGBE_READ_REG(hw, IXGBE_SWFW_SYNC);
		if (swfw_sync & (fwmask | hwmask)) {
			if (ixgbe_get_swfw_sync_semaphore(hw))
				return IXGBE_ERR_SWFW_SYNC;

			swfw_sync |= swmask;
			IXGBE_WRITE_REG(hw, IXGBE_SWFW_SYNC, swfw_sync);
			ixgbe_release_swfw_sync_semaphore(hw);
		}
	}

	msleep(5);
	return 0;
}

/**
 * ixgbe_release_swfw_sync_X540 - Release SWFW semaphore
 * @hw: pointer to hardware structure
 * @mask: Mask to specify which semaphore to release
 *
 * Releases the SWFW semaphore throught the SW_FW_SYNC register
 * for the specified function (CSR, PHY0, PHY1, EVM, Flash)
 **/
static void ixgbe_release_swfw_sync_X540(struct ixgbe_hw *hw, u16 mask)
{
	u32 swfw_sync;
	u32 swmask = mask;

	ixgbe_get_swfw_sync_semaphore(hw);

	swfw_sync = IXGBE_READ_REG(hw, IXGBE_SWFW_SYNC);
	swfw_sync &= ~swmask;
	IXGBE_WRITE_REG(hw, IXGBE_SWFW_SYNC, swfw_sync);

	ixgbe_release_swfw_sync_semaphore(hw);
	msleep(5);
}

/**
 * ixgbe_get_nvm_semaphore - Get hardware semaphore
 * @hw: pointer to hardware structure
 *
 * Sets the hardware semaphores so SW/FW can gain control of shared resources
 **/
static s32 ixgbe_get_swfw_sync_semaphore(struct ixgbe_hw *hw)
{
	s32 status = IXGBE_ERR_EEPROM;
	u32 timeout = 2000;
	u32 i;
	u32 swsm;

	/* Get SMBI software semaphore between device drivers first */
	for (i = 0; i < timeout; i++) {
		/*
		 * If the SMBI bit is 0 when we read it, then the bit will be
		 * set and we have the semaphore
		 */
		swsm = IXGBE_READ_REG(hw, IXGBE_SWSM);
		if (!(swsm & IXGBE_SWSM_SMBI)) {
			status = 0;
			break;
		}
		udelay(50);
	}

	/* Now get the semaphore between SW/FW through the REGSMP bit */
	if (status) {
		for (i = 0; i < timeout; i++) {
			swsm = IXGBE_READ_REG(hw, IXGBE_SWFW_SYNC);
			if (!(swsm & IXGBE_SWFW_REGSMP))
				break;

			udelay(50);
		}
	} else {
		hw_dbg(hw, "Software semaphore SMBI between device drivers "
		           "not granted.\n");
	}

	return status;
}

/**
 * ixgbe_release_nvm_semaphore - Release hardware semaphore
 * @hw: pointer to hardware structure
 *
 * This function clears hardware semaphore bits.
 **/
static void ixgbe_release_swfw_sync_semaphore(struct ixgbe_hw *hw)
{
	 u32 swsm;

	/* Release both semaphores by writing 0 to the bits REGSMP and SMBI */

	swsm = IXGBE_READ_REG(hw, IXGBE_SWSM);
	swsm &= ~IXGBE_SWSM_SMBI;
	IXGBE_WRITE_REG(hw, IXGBE_SWSM, swsm);

	swsm = IXGBE_READ_REG(hw, IXGBE_SWFW_SYNC);
	swsm &= ~IXGBE_SWFW_REGSMP;
	IXGBE_WRITE_REG(hw, IXGBE_SWFW_SYNC, swsm);

	IXGBE_WRITE_FLUSH(hw);
}

static struct ixgbe_mac_operations mac_ops_X540 = {
	.init_hw                = &ixgbe_init_hw_generic,
	.reset_hw               = &ixgbe_reset_hw_X540,
	.start_hw               = &ixgbe_start_hw_generic,
	.clear_hw_cntrs         = &ixgbe_clear_hw_cntrs_generic,
	.get_media_type         = &ixgbe_get_media_type_X540,
	.get_supported_physical_layer =
                                  &ixgbe_get_supported_physical_layer_X540,
	.enable_rx_dma          = &ixgbe_enable_rx_dma_generic,
	.get_mac_addr           = &ixgbe_get_mac_addr_generic,
	.get_san_mac_addr       = &ixgbe_get_san_mac_addr_generic,
	.get_device_caps        = NULL,
	.get_wwn_prefix         = &ixgbe_get_wwn_prefix_generic,
	.stop_adapter           = &ixgbe_stop_adapter_generic,
	.get_bus_info           = &ixgbe_get_bus_info_generic,
	.set_lan_id             = &ixgbe_set_lan_id_multi_port_pcie,
	.read_analog_reg8       = NULL,
	.write_analog_reg8      = NULL,
	.setup_link             = &ixgbe_setup_mac_link_X540,
	.check_link             = &ixgbe_check_mac_link_generic,
	.get_link_capabilities  = &ixgbe_get_copper_link_capabilities_generic,
	.led_on                 = &ixgbe_led_on_generic,
	.led_off                = &ixgbe_led_off_generic,
	.blink_led_start        = &ixgbe_blink_led_start_generic,
	.blink_led_stop         = &ixgbe_blink_led_stop_generic,
	.set_rar                = &ixgbe_set_rar_generic,
	.clear_rar              = &ixgbe_clear_rar_generic,
	.set_vmdq               = &ixgbe_set_vmdq_generic,
	.clear_vmdq             = &ixgbe_clear_vmdq_generic,
	.init_rx_addrs          = &ixgbe_init_rx_addrs_generic,
	.update_uc_addr_list    = &ixgbe_update_uc_addr_list_generic,
	.update_mc_addr_list    = &ixgbe_update_mc_addr_list_generic,
	.enable_mc              = &ixgbe_enable_mc_generic,
	.disable_mc             = &ixgbe_disable_mc_generic,
	.clear_vfta             = &ixgbe_clear_vfta_generic,
	.set_vfta               = &ixgbe_set_vfta_generic,
	.fc_enable              = &ixgbe_fc_enable_generic,
	.init_uta_tables        = &ixgbe_init_uta_tables_generic,
	.setup_sfp              = NULL,
	.set_mac_anti_spoofing  = &ixgbe_set_mac_anti_spoofing,
	.set_vlan_anti_spoofing = &ixgbe_set_vlan_anti_spoofing,
};

static struct ixgbe_eeprom_operations eeprom_ops_X540 = {
	.init_params            = &ixgbe_init_eeprom_params_X540,
	.read                   = &ixgbe_read_eerd_X540,
	.write                  = &ixgbe_write_eewr_X540,
	.calc_checksum		= &ixgbe_calc_eeprom_checksum_X540,
	.validate_checksum      = &ixgbe_validate_eeprom_checksum_generic,
	.update_checksum        = &ixgbe_update_eeprom_checksum_X540,
};

static struct ixgbe_phy_operations phy_ops_X540 = {
	.identify               = &ixgbe_identify_phy_generic,
	.identify_sfp           = &ixgbe_identify_sfp_module_generic,
	.init			= NULL,
	.reset                  = &ixgbe_reset_phy_generic,
	.read_reg               = &ixgbe_read_phy_reg_generic,
	.write_reg              = &ixgbe_write_phy_reg_generic,
	.setup_link             = &ixgbe_setup_phy_link_generic,
	.setup_link_speed       = &ixgbe_setup_phy_link_speed_generic,
	.read_i2c_byte          = &ixgbe_read_i2c_byte_generic,
	.write_i2c_byte         = &ixgbe_write_i2c_byte_generic,
	.read_i2c_eeprom        = &ixgbe_read_i2c_eeprom_generic,
	.write_i2c_eeprom       = &ixgbe_write_i2c_eeprom_generic,
	.check_overtemp         = &ixgbe_tn_check_overtemp,
};

struct ixgbe_info ixgbe_X540_info = {
	.mac                    = ixgbe_mac_X540,
	.get_invariants         = &ixgbe_get_invariants_X540,
	.mac_ops                = &mac_ops_X540,
	.eeprom_ops             = &eeprom_ops_X540,
	.phy_ops                = &phy_ops_X540,
	.mbx_ops                = &mbx_ops_generic,
};
