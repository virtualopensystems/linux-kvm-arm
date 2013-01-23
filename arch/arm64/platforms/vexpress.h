#ifndef __MACH_MOTHERBOARD_H
#define __MACH_MOTHERBOARD_H

/* CS register bases for the extended memory map. */
#define V2M_PA_CS0		0x08000000
#define V2M_PA_CS3		0x18000000
#define V2M_PA_CS7		0x1c000000

#define V2M_PERIPH_SHIFT	16
#define V2M_PERIPH_OFFSET(x)	(x << V2M_PERIPH_SHIFT)

#define V2M_NOR0		(V2M_PA_CS0 + V2M_PERIPH_OFFSET(0))
#define V2M_VIDEO_SRAM		(V2M_PA_CS3 + V2M_PERIPH_OFFSET(0))
#define V2M_MMCI		(V2M_PA_CS7 + V2M_PERIPH_OFFSET(5))
#define V2M_CLCD		(V2M_PA_CS7 + V2M_PERIPH_OFFSET(31))

/* System register offsets. */
#define V2M_SYS_ID		0x000
#define V2M_SYS_SW		0x004
#define V2M_SYS_LED		0x008
#define V2M_SYS_100HZ		0x024
#define V2M_SYS_FLAGS		0x030
#define V2M_SYS_FLAGSSET	0x030
#define V2M_SYS_FLAGSCLR	0x034
#define V2M_SYS_NVFLAGS		0x038
#define V2M_SYS_NVFLAGSSET	0x038
#define V2M_SYS_NVFLAGSCLR	0x03c
#define V2M_SYS_MCI		0x048
#define V2M_SYS_FLASH		0x03c
#define V2M_SYS_CFGSW		0x058
#define V2M_SYS_24MHZ		0x05c
#define V2M_SYS_MISC		0x060
#define V2M_SYS_DMA		0x064
#define V2M_SYS_PROCID0		0x084
#define V2M_SYS_PROCID1		0x088
#define V2M_SYS_CFGDATA		0x0a0
#define V2M_SYS_CFGCTRL		0x0a4
#define V2M_SYS_CFGSTAT		0x0a8

/*
 * Configuration
 */
#define SYS_CFG_START		(1 << 31)
#define SYS_CFG_WRITE		(1 << 30)
#define SYS_CFG_OSC		(1 << 20)
#define SYS_CFG_VOLT		(2 << 20)
#define SYS_CFG_AMP		(3 << 20)
#define SYS_CFG_TEMP		(4 << 20)
#define SYS_CFG_RESET		(5 << 20)
#define SYS_CFG_SCC		(6 << 20)
#define SYS_CFG_MUXFPGA		(7 << 20)
#define SYS_CFG_SHUTDOWN	(8 << 20)
#define SYS_CFG_REBOOT		(9 << 20)
#define SYS_CFG_DVIMODE		(11 << 20)
#define SYS_CFG_POWER		(12 << 20)
#define SYS_CFG_SITE_MB		(0 << 16)
#define SYS_CFG_SITE_DB1	(1 << 16)
#define SYS_CFG_SITE_DB2	(2 << 16)
#define SYS_CFG_STACK(n)	((n) << 12)

#define SYS_CFG_ERR		(1 << 1)
#define SYS_CFG_COMPLETE	(1 << 0)

#endif
