#    Makefile - build a test suite form ARM/Thumb-2 MMIO emulation
#    Copyright (C) 2012 Christoffer Dall <cdall@cs.columbia.edu>
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.# 

GCC=$(CROSS_COMPILE)gcc
CC=$(CROSS_COMPILE)gcc
AS=$(CROSS_COMPILE)as
LD=$(CROSS_COMPILE)ld
OBJCOPY=$(CROSS_COMPILE)objcopy

LDFLAGS = -static

CFLAGS = -Wall -I../../../../../include -I../../../../../arch/arm/include -D__EXPORTED_HEADERS__

TESTS=mmio

GUESTS=$(TESTS:%=%-guest.bin)
HOST_DRIVERS=$(TESTS:%=%-host.o)

all: guest-driver $(GUESTS)

DRIVER_OBJS = guest-driver.o $(HOST_DRIVERS)
guest-driver: $(DRIVER_OBJS)
	$(GCC) $(LDFLAGS) -o $@ $(DRIVER_OBJS)

%-guest.o: %-guest.S
	$(GCC) $(CFLAGS) -fno-builtin -ffreestanding -c -o $@ $<

%-guest: %-guest.o guest.lds
	$(LD) -o $@ --script=guest.lds $< 

%-guest.bin: %-guest
	$(OBJCOPY) -O binary $< $@

%.o: %.c
	$(CC) $(CFLAGS) -g -c -o $@ $<

clean distclean:
	rm -f $(GUESTS) $(HOST_DRIVERS) guest-driver $(OBJS)

# This assumes we're not cross-compiling!
run_tests: all
	./guest-driver mmio-guest.bin

.PHONY: clean distclean headers
