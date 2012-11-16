/*
 * mmio-guest.lds.S - linker script for MMIO guest
 * Copyright (C) 2012 Christoffer Dall <cdall@cs.columbia.edu>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 2, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

OUTPUT_ARCH(arm)

PHYS_OFFSET     = 0xFFFE0000;
EXCEPTION_TABLE = 0xFFFF0000;

SECTIONS
{
 . = PHYS_OFFSET;
 .text : { *(.start) *(.text) }
 .data : { *(.data) }
 .bss : { *(.bss) }

 . = EXCEPTION_TABLE;
 stacktop = .;

 .extable : { *(.text.extable) }
}
