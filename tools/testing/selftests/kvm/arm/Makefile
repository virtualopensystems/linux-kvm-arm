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

all: guest-driver mmio-guest.bin

DRIVER_OBJS = guest-driver.o mmio-host.o
guest-driver: $(DRIVER_OBJS)
	$(GCC) $(LDFLAGS) -o $@ $(DRIVER_OBJS)

mmio-guest.o: mmio-guest.S
	$(GCC) $(CFLAGS) -fno-builtin -ffreestanding -c -o $@ $<

mmio-guest: mmio-guest.o mmio-guest.lds
	$(LD) -o $@ --script=mmio-guest.lds $< 

mmio-guest.bin: mmio-guest
	$(OBJCOPY) -O binary $< $@

OBJS	= mmio-guest.o $(DRIVER_OBJS)

%.o: %.c
	$(CC) $(CFLAGS) -g -c -o $@ $<

clean distclean:
	rm -f mmio-guest mmio-guest.bin guest-driver $(OBJS)

.PHONY: clean distclean headers
