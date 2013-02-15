#    Makefile - build a test suite for KVM/ARM
#    Copyright (C) 2012 Christoffer Dall <cdall@cs.columbia.edu>
#                  2012 Rusty Russell <rusty.russell@linaro.org>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License, version 2, as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

GCC=$(CROSS_COMPILE)gcc
CC=$(CROSS_COMPILE)gcc
AS=$(CROSS_COMPILE)as
LD=$(CROSS_COMPILE)ld
OBJCOPY=$(CROSS_COMPILE)objcopy

LDFLAGS = -static

KERNEL_DIR ?= ../../../../..
KDIR = $(shell echo $(KERNEL_DIR))

CFLAGS = -I$(KDIR)/include/uapi \
	 -I$(KDIR)/include \
	 -I$(KDIR)/arch/arm/include/uapi \
	 -I$(KDIR)/arch/arm/include \
	 -Wall -D__EXPORTED_HEADERS__ -marm

TESTS=mmio vfp cond cp15 helloworld vmexit

GUESTS=$(TESTS:%=%-guest)
HOST_DRIVERS=$(TESTS:%=%-host.o)

# We assume 32 fp regs here.
CFLAGS_vfp-host.o := -mfpu=vfpv3
CFLAGS_vfp-guest.o := -mfpu=vfpv3

all: guest-driver $(GUESTS)

DRIVER_OBJS = guest-driver.o $(HOST_DRIVERS)
guest-driver: $(DRIVER_OBJS)
	$(GCC) $(LDFLAGS) -o $@ $(DRIVER_OBJS)

guest-base.o: guest-base.S
	$(GCC) $(CFLAGS) -fno-builtin -ffreestanding -O2 -c -o $@ $<

lib1funcs.o: lib1funcs.S
	$(GCC) $(CFLAGS) $(CFLAGS_$@) -fno-builtin -ffreestanding -O2 -c -o $@ $<

guest-util.o: guest-util.c
	$(GCC) $(CFLAGS) $(CFLAGS_$@) -fno-builtin -ffreestanding -O2 -c -o $@ $<

%-guest.o: %-guest.c
	$(GCC) $(CFLAGS) $(CFLAGS_$@) -fno-builtin -ffreestanding -O2 -c -o $@ $<

%-guest: %-guest.o guest.lds guest-base.o guest-util.o lib1funcs.o
	$(LD) -o $@ --script=guest.lds $< guest-base.o guest-util.o lib1funcs.o

%-host.o: %-host.c
	$(GCC) $(CFLAGS) $(CFLAGS_$@) -O2 -c -o $@ $<

clean distclean:
	rm -f $(GUESTS) $(HOST_DRIVERS) guest-driver guest-base.o $(OBJS)

# This assumes we're not cross-compiling!
run_tests: all
	./guest-driver mmio-guest.bin

install: all
	cp guest-driver $(GUESTS) $(DESTDIR)

.PHONY: clean distclean headers
