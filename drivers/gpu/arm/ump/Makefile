#
# Copyright (C) 2010 ARM Limited. All rights reserved.
# 
# This program is free software and is provided to you under the terms of the GNU General Public License version 2
# as published by the Free Software Foundation, and any use by you of this program is subject to the terms of such GNU licence.
# 
# A copy of the licence is included with the program, and can also be obtained from Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#

ifeq ($(CONFIG_USING_OS_MEMORY),y)
USING_MEMORY_TYPE=1
endif

UMP_FILE_PREFIX = 
UDD_FILE_PREFIX := drivers/gpu/arm/ump/

# For each arch check: CROSS_COMPILE , KDIR , CFLAGS += -DARCH

## @note Should allow overriding of building UMP for non-debug:

ifeq (($CONFIG_UMP_DEBUG),y)
EXTRA_CFLAGS += -DDEBUG
endif

USING_MEMORY_TYPE ?=0 # 0: dedicated memory 1: OS memory

EXTRA_CFLAGS += -I$(UDD_FILE_PREFIX) -I$(UDD_FILE_PREFIX)/common -I$(UDD_FILE_PREFIX)/linux -I$(UDD_FILE_PREFIX)/../mali/common -I$(UDD_FILE_PREFIX)/../mali/linux -I$(UDD_FILE_PREFIX)/include

EXTRA_CFLAGS += -DUMP_MEMORY_TYPE=$(USING_MEMORY_TYPE)
# For customer releases the Linux Device Drivers will be provided as ARM proprietary and GPL releases:
# The ARM proprietary product will only include the license/proprietary directory
# The GPL product will only include the license/gpl directory

ifeq ($(wildcard $(UDD_FILE_PREFIX)/linux/license/gpl/*),)
EXTRA_CFLAGS += -I$(UDD_FILE_PREFIX)/linux/license/proprietary
else
EXTRA_CFLAGS += -I$(UDD_FILE_PREFIX)/linux/license/gpl
endif

obj-$(CONFIG_UMP)       += ump.o

ump-y:=	$(UMP_FILE_PREFIX)common/ump_kernel_common.o \
	$(UMP_FILE_PREFIX)common/ump_kernel_descriptor_mapping.o \
	$(UMP_FILE_PREFIX)common/ump_kernel_api.o \
	$(UMP_FILE_PREFIX)common/ump_kernel_ref_drv.o \
	$(UMP_FILE_PREFIX)linux/ump_kernel_linux.o \
	$(UMP_FILE_PREFIX)linux/ump_kernel_memory_backend_os.o \
	$(UMP_FILE_PREFIX)linux/ump_kernel_memory_backend_dedicated.o \
	$(UMP_FILE_PREFIX)linux/ump_memory_backend.o \
	$(UMP_FILE_PREFIX)linux/ump_ukk_wrappers.o \
	$(UMP_FILE_PREFIX)linux/ump_ukk_ref_wrappers.o \
	$(UMP_FILE_PREFIX)linux/ump_osk_atomics.o \
	$(UMP_FILE_PREFIX)linux/ump_osk_low_level_mem.o \
	$(UMP_FILE_PREFIX)linux/ump_osk_misc.o \
	$(UMP_FILE_PREFIX)../mali/linux/mali_osk_atomics.o \
	$(UMP_FILE_PREFIX)../mali/linux/mali_osk_locks.o \
	$(UMP_FILE_PREFIX)../mali/linux/mali_osk_memory.o \
	$(UMP_FILE_PREFIX)../mali/linux/mali_osk_math.o \
	$(UMP_FILE_PREFIX)../mali/linux/mali_osk_misc.o

# Get subversion revision number, fall back to 0000 if no svn info is available
SVN_REV:=$(shell ((svnversion | grep -qv exported && echo -n 'Revision: ' && svnversion) || git svn info | sed -e 's/$$$$/M/' | grep '^Revision: ' || echo ${MALI_RELEASE_NAME}) 2>/dev/null | sed -e 's/^Revision: //')
		
EXTRA_CFLAGS += -DSVN_REV=$(SVN_REV)
EXTRA_CFLAGS += -DSVN_REV_STRING=\"$(SVN_REV)\"

