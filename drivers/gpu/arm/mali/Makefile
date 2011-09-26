#
# Copyright (C) 2010 ARM Limited. All rights reserved.
# 
# This program is free software and is provided to you under the terms of the GNU General Public License version 2
# as published by the Free Software Foundation, and any use by you of this program is subject to the terms of such GNU licence.
# 
# A copy of the licence is included with the program, and can also be obtained from Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#

OSKOS :=linux
FILES_PREFIX=
MALI_FILE_PREFIX := $(srctree)/drivers/gpu/arm/mali
KBUILDROOT =

# Add platform configuration file for Mali
ifeq ($(CONFIG_ARCH_EXYNOS4),y)
MACHDIR  := $(srctree)/arch/arm/mach-exynos4
MALICONFIGDIR :=$(MACHDIR)/include/mach/mali
endif

ifeq ($(CONFIG_USING_MMU),y)
USING_MMU=1
endif

ifeq ($(CONFIG_USING_UMP),y)
USING_UMP=1
endif

ifeq ($(CONFIG_USING_MMU),y)
USING_MMU=1
endif

ifeq ($(CONFIG_ONLY_ZBT),y)
ONLY_ZBT =1
endif

ifeq ($(CONFIG_USING_OS_MEMORY),y)
USING_OS_MEMORY=1
endif

ifeq ($(CONFIG_USING_PMM),y)
USING_PMM=1
endif

ifeq ($(CONFIG_USING_GPU_UTILIZATION),y)
USING_GPU_UTILIZATION =1
endif

ifeq ($(CONFIG_USING_MALI_RUN_TIME_PM),y)
USING_MALI_RUN_TIME_PM =1
endif

ifeq ($(CONFIG_USING_MALI_PMM_TESTSUITE),y)
USING_MALI_PMM_TESTSUITE=1
endif

ifeq ($(CONFIG_USING_PROFILING),y)
USING_PROFILING =1
endif

# set up defaults if not defined by the user
ARCH ?= arm
USING_MMU ?= 1
USING_UMP ?= 0
ONLY_ZBT ?= 0
USING_ZBT ?= 1
USING_OS_MEMORY ?= 0
USING_PMM ?= 0
USING_GPU_UTILIZATION ?= 0
USING_MALI_RUN_TIME_PM ?= 0
USING_MALI_PMM_TESTSUITE ?= 0
USING_PROFILING ?= 0
TIMESTAMP ?= default
TARGET_PLATFORM ?= default

ifeq ($(USING_UMP),1)
	UMP_SYMVERS_FILE = ../ump/Module.symvers
	KBUILD_EXTRA_SYMBOLS = $(KBUILD_EXTMOD)/$(UMP_SYMVERS_FILE)
endif

# Check if a Mali Core sub module should be enabled, true or false returned
submodule_enabled = $(shell gcc $(DEFINES) -E $(MALICONFIGDIR)/config.h | grep type | grep -c $(2))

# Set up our defines, which will be passed to gcc
DEFINES += -DUSING_ZBT=$(USING_ZBT)
DEFINES += -DUSING_OS_MEMORY=$(USING_OS_MEMORY)
DEFINES += -DUSING_MMU=$(USING_MMU)
DEFINES += -DUSING_UMP=$(USING_UMP)
DEFINES += -DONLY_ZBT=$(ONLY_ZBT)
DEFINES += -D_MALI_OSK_SPECIFIC_INDIRECT_MMAP
DEFINES += -DMALI_TIMELINE_PROFILING_ENABLED=$(USING_PROFILING)
DEFINES += -DMALI_POWER_MGMT_TEST_SUITE=$(USING_MALI_PMM_TESTSUITE)
DEFINES += -DMALI_PMM_RUNTIME_JOB_CONTROL_ON=$(USING_MALI_RUN_TIME_PM)

ifneq ($(call submodule_enabled, $M, PMU),0)
        MALI_PLATFORM_FILE = platform/mali400-pmu/mali_platform.o
else
        MALI_PLATFORM_FILE = platform/$(TARGET_PLATFORM)/mali_platform.o
endif

DEFINES += -DUSING_MALI_PMM=$(USING_PMM)
DEFINES += -DMALI_GPU_UTILIZATION=$(USING_GPU_UTILIZATION)

ifeq ($(CONFIG_DEBUG_BUILD),y)
DEFINES += -DDEBUG
endif
DEFINES += -DSVN_REV=$(SVN_REV)
DEFINES += -DSVN_REV_STRING=\"$(SVN_REV)\"

# Linux has its own mmap cleanup handlers (see mali_kernel_mem_mmu.c)
DEFINES += -DMALI_UKK_HAS_IMPLICIT_MMAP_CLEANUP

ifeq ($(USING_UMP),1)
	DEFINES += -DMALI_USE_UNIFIED_MEMORY_PROVIDER=1
	EXTRA_CFLAGS += -I$(MALI_FILE_PREFIX)/../ump/include
else
	DEFINES += -DMALI_USE_UNIFIED_MEMORY_PROVIDER=0
endif

# Target build file
obj-$(CONFIG_MALI400MP)		+= mali.o

# Use our defines when compiling
EXTRA_CFLAGS += $(DEFINES) -I$(MALI_FILE_PREFIX) -I$(MALI_FILE_PREFIX)/common -I$(MALI_FILE_PREFIX)/linux -I$(MALI_FILE_PREFIX)/platform

ifneq ($(CONFIG_UMP),y)
OSKFILES=$(FILES_PREFIX)$(OSKOS)/mali_osk_atomics.o \
        $(FILES_PREFIX)$(OSKOS)/mali_osk_locks.o \
        $(FILES_PREFIX)$(OSKOS)/mali_osk_math.o \
        $(FILES_PREFIX)$(OSKOS)/mali_osk_memory.o \
        $(FILES_PREFIX)$(OSKOS)/mali_osk_misc.o
endif
OSKFILES+=\
        $(FILES_PREFIX)$(OSKOS)/mali_osk_irq.o \
        $(FILES_PREFIX)$(OSKOS)/mali_osk_low_level_mem.o \
        $(FILES_PREFIX)$(OSKOS)/mali_osk_mali.o \
        $(FILES_PREFIX)$(OSKOS)/mali_osk_notification.o \
        $(FILES_PREFIX)$(OSKOS)/mali_osk_time.o \
        $(FILES_PREFIX)$(OSKOS)/mali_osk_timers.o

UKKFILES=\
        $(FILES_PREFIX)$(OSKOS)/mali_ukk_mem.o \
        $(FILES_PREFIX)$(OSKOS)/mali_ukk_gp.o \
        $(FILES_PREFIX)$(OSKOS)/mali_ukk_pp.o \
        $(FILES_PREFIX)$(OSKOS)/mali_ukk_core.o

ifeq ($(USING_PROFILING),1)
UKKFILES+=\
        $(FILES_PREFIX)$(OSKOS)/mali_ukk_profiling.o
endif

# For customer releases the Linux Device Drivers will be provided as ARM proprietary and GPL releases:
# The ARM proprietary product will only include the license/proprietary directory
# The GPL product will only include the license/gpl directory

ifeq ($(wildcard $(MALI_FILE_PREFIX)/linux/license/gpl/*),)
EXTRA_CFLAGS += -I$(MALI_FILE_PREFIX)/linux/license/proprietary
else
EXTRA_CFLAGS += -I$(MALI_FILE_PREFIX)/linux/license/gpl
endif
EXTRA_CFLAGS += -I$(MALI_FILE_PREFIX)/common/pmm

# Source files which always are included in a build
mali-y := \
	common/mali_kernel_core.o \
	linux/mali_kernel_linux.o \
	$(OSKOS)/mali_osk_indir_mmap.o \
	common/mali_kernel_rendercore.o \
	common/mali_kernel_descriptor_mapping.o \
	$(MALI_PLATFORM_FILE) \
	$(OSKFILES) \
	$(UKKFILES)
	
ifeq ($(USING_PROFILING),1)
mali-y += \
	common/mali_kernel_profiling.o \
	timestamp-$(TIMESTAMP)/mali_timestamp.o
EXTRA_CFLAGS += -I$(MALI_FILE_PREFIX)/timestamp-$(TIMESTAMP)
endif

# Selecting files to compile by parsing the config file

ifeq ($(USING_PMM),1)
mali-y += \
	common/pmm/mali_pmm.o \
	common/pmm/mali_pmm_policy.o \
	common/pmm/mali_pmm_policy_alwayson.o \
	common/pmm/mali_pmm_policy_jobcontrol.o \
	common/pmm/mali_pmm_state.o \
	linux/mali_kernel_pm.o \
	linux/mali_osk_pm.o \
	linux/mali_device_pause_resume.o 
endif

ifeq ($(USING_GPU_UTILIZATION),1)
mali-y += \
	common/mali_kernel_utilization.o
endif

ifneq ($(call submodule_enabled, $M, MALI400PP),0)
	# Mali-400 PP in use
	EXTRA_CFLAGS += -DUSING_MALI400
	mali-y += common/mali_kernel_MALI200.o
endif

ifneq ($(call submodule_enabled, $M, MALI400GP),0)
	# Mali-400 GP in use
	mali-y += common/mali_kernel_GP2.o
endif

ifneq ($(call submodule_enabled, $M, MALI300PP),0)
	# Mali-400 PP in use
	EXTRA_CFLAGS += -DUSING_MALI400
	mali-y += common/mali_kernel_MALI200.o
endif

ifneq ($(call submodule_enabled, $M, MALI300GP),0)
	# Mali-400 GP in use
	mali-y += common/mali_kernel_GP2.o
endif

ifneq ($(call submodule_enabled, $M, MALI200),0)
	# Mali200 in use
	EXTRA_CFLAGS += -DUSING_MALI200
	mali-y += common/mali_kernel_MALI200.o
endif

ifneq ($(call submodule_enabled, $M, MALIGP2),0)
	# MaliGP2 in use
	mali-y += common/mali_kernel_GP2.o
endif

ifneq ($(call submodule_enabled, $M, MMU),0)
	# Mali MMU in use
	mali-y += common/mali_kernel_mem_mmu.o common/mali_kernel_memory_engine.o common/mali_block_allocator.o common/mali_kernel_mem_os.o
else
	# No Mali MMU in use
	mali-y += common/mali_kernel_mem_buddy.o
endif

ifneq ($(call submodule_enabled, $M, MALI400L2)$(),0)
	# Mali Level2 cache in use
	EXTRA_CFLAGS += -DUSING_MALI400_L2_CACHE
	mali-y += common/mali_kernel_l2_cache.o
endif

ifneq ($(call submodule_enabled, $M, MALI300L2)$(),0)
	# Mali Level2 cache in use
	EXTRA_CFLAGS += -DUSING_MALI400_L2_CACHE
	mali-y += common/mali_kernel_l2_cache.o
endif

