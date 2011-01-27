/*
 * linux/drivers/video/omap2/dss/dss_features.h
 *
 * Copyright (C) 2010 Texas Instruments
 * Author: Archit Taneja <archit@ti.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __OMAP2_DSS_FEATURES_H
#define __OMAP2_DSS_FEATURES_H

#define MAX_DSS_MANAGERS	3
#define MAX_DSS_OVERLAYS	3

/* DSS has feature id */
enum dss_feat_id {
	FEAT_GLOBAL_ALPHA	= 1 << 0,
	FEAT_GLOBAL_ALPHA_VID1	= 1 << 1,
	FEAT_PRE_MULT_ALPHA	= 1 << 2,
	FEAT_LCDENABLEPOL	= 1 << 3,
	FEAT_LCDENABLESIGNAL	= 1 << 4,
	FEAT_PCKFREEENABLE	= 1 << 5,
	FEAT_FUNCGATED		= 1 << 6,
	FEAT_MGR_LCD2		= 1 << 7,
};

/* DSS register field id */
enum dss_feat_reg_field {
	FEAT_REG_FIRHINC,
	FEAT_REG_FIRVINC,
	FEAT_REG_FIFOHIGHTHRESHOLD,
	FEAT_REG_FIFOLOWTHRESHOLD,
	FEAT_REG_FIFOSIZE,
};

/* DSS Feature Functions */
int dss_feat_get_num_mgrs(void);
int dss_feat_get_num_ovls(void);
enum omap_display_type dss_feat_get_supported_displays(enum omap_channel channel);
enum omap_color_mode dss_feat_get_supported_color_modes(enum omap_plane plane);
bool dss_feat_color_mode_supported(enum omap_plane plane,
		enum omap_color_mode color_mode);

bool dss_has_feature(enum dss_feat_id id);
void dss_feat_get_reg_field(enum dss_feat_reg_field id, u8 *start, u8 *end);
void dss_features_init(void);
#endif
