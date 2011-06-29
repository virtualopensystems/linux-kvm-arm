#ifndef __MACH_MOTHERBOARD_H
#define __MACH_MOTHERBOARD_H

/*
 * Physical addresses, offset from V2M_PA_CS0-3
 */
#define V2M_NOR0		(V2M_PA_CS0)
#define V2M_NOR1		(V2M_PA_CS1)
#define V2M_SRAM		(V2M_PA_CS2)
#define V2M_VIDEO_SRAM		(V2M_PA_CS3 + 0x00000000)
#define V2M_LAN9118		(V2M_PA_CS3 + 0x02000000)
#define V2M_ISP1761		(V2M_PA_CS3 + 0x03000000)

/*
 * Physical addresses, offset from V2M_PA_CS7
 */
#ifdef CONFIG_VEXPRESS_ORIGINAL_MEMORY_MAP
/* CS register bases for the original memory map. */
#define V2M_PA_CS0		0x40000000
#define V2M_PA_CS1		0x44000000
#define V2M_PA_CS2		0x48000000
#define V2M_PA_CS3		0x4c000000
#define V2M_PA_CS7		0x10000000

#define V2M_PERIPH_OFFSET(x)	(x << 12)
#define V2M_SYSREGS		(V2M_PA_CS7 + V2M_PERIPH_OFFSET(0))
#define V2M_SYSCTL		(V2M_PA_CS7 + V2M_PERIPH_OFFSET(1))
#define V2M_SERIAL_BUS_PCI	(V2M_PA_CS7 + V2M_PERIPH_OFFSET(2))

#elif defined(CONFIG_VEXPRESS_EXTENDED_MEMORY_MAP)
/* CS register bases for the extended memory map. */
#define V2M_PA_CS0		0x08000000
#define V2M_PA_CS1		0x0c000000
#define V2M_PA_CS2		0x14000000
#define V2M_PA_CS3		0x18000000
#define V2M_PA_CS7		0x1c000000

#define V2M_PERIPH_OFFSET(x)	(x << 16)
#define V2M_SYSREGS		(V2M_PA_CS7 + V2M_PERIPH_OFFSET(1))
#define V2M_SYSCTL		(V2M_PA_CS7 + V2M_PERIPH_OFFSET(2))
#define V2M_SERIAL_BUS_PCI	(V2M_PA_CS7 + V2M_PERIPH_OFFSET(3))
#endif

/* Common peripherals relative to CS7. */
#define V2M_AACI		(V2M_PA_CS7 + V2M_PERIPH_OFFSET(4))
#define V2M_MMCI		(V2M_PA_CS7 + V2M_PERIPH_OFFSET(5))
#define V2M_KMI0		(V2M_PA_CS7 + V2M_PERIPH_OFFSET(6))
#define V2M_KMI1		(V2M_PA_CS7 + V2M_PERIPH_OFFSET(7))

#define V2M_UART0		(V2M_PA_CS7 + V2M_PERIPH_OFFSET(9))
#define V2M_UART1		(V2M_PA_CS7 + V2M_PERIPH_OFFSET(10))
#define V2M_UART2		(V2M_PA_CS7 + V2M_PERIPH_OFFSET(11))
#define V2M_UART3		(V2M_PA_CS7 + V2M_PERIPH_OFFSET(12))

#define V2M_WDT			(V2M_PA_CS7 + V2M_PERIPH_OFFSET(15))

#define V2M_TIMER01		(V2M_PA_CS7 + V2M_PERIPH_OFFSET(17))
#define V2M_TIMER23		(V2M_PA_CS7 + V2M_PERIPH_OFFSET(18))

#define V2M_SERIAL_BUS_DVI	(V2M_PA_CS7 + V2M_PERIPH_OFFSET(22))
#define V2M_RTC			(V2M_PA_CS7 + V2M_PERIPH_OFFSET(23))

#define V2M_CF			(V2M_PA_CS7 + V2M_PERIPH_OFFSET(26))

#define V2M_CLCD		(V2M_PA_CS7 + V2M_PERIPH_OFFSET(31))
#define V2M_SIZE_CS7		V2M_PERIPH_OFFSET(32)

/* System register offsets. */
#define V2M_SYS_ID		(V2M_SYSREGS + 0x000)
#define V2M_SYS_SW		(V2M_SYSREGS + 0x004)
#define V2M_SYS_LED		(V2M_SYSREGS + 0x008)
#define V2M_SYS_100HZ		(V2M_SYSREGS + 0x024)
#define V2M_SYS_FLAGS		(V2M_SYSREGS + 0x030)
#define V2M_SYS_FLAGSSET	(V2M_SYSREGS + 0x030)
#define V2M_SYS_FLAGSCLR	(V2M_SYSREGS + 0x034)
#define V2M_SYS_NVFLAGS		(V2M_SYSREGS + 0x038)
#define V2M_SYS_NVFLAGSSET	(V2M_SYSREGS + 0x038)
#define V2M_SYS_NVFLAGSCLR	(V2M_SYSREGS + 0x03c)
#define V2M_SYS_MCI		(V2M_SYSREGS + 0x048)
#define V2M_SYS_FLASH		(V2M_SYSREGS + 0x03c)
#define V2M_SYS_CFGSW		(V2M_SYSREGS + 0x058)
#define V2M_SYS_24MHZ		(V2M_SYSREGS + 0x05c)
#define V2M_SYS_MISC		(V2M_SYSREGS + 0x060)
#define V2M_SYS_DMA		(V2M_SYSREGS + 0x064)
#define V2M_SYS_PROCID0		(V2M_SYSREGS + 0x084)
#define V2M_SYS_PROCID1		(V2M_SYSREGS + 0x088)
#define V2M_SYS_CFGDATA		(V2M_SYSREGS + 0x0a0)
#define V2M_SYS_CFGCTRL		(V2M_SYSREGS + 0x0a4)
#define V2M_SYS_CFGSTAT		(V2M_SYSREGS + 0x0a8)

#define V2M_TIMER0		(V2M_TIMER01 + 0x000)
#define V2M_TIMER1		(V2M_TIMER01 + 0x020)

#define V2M_TIMER2		(V2M_TIMER23 + 0x000)
#define V2M_TIMER3		(V2M_TIMER23 + 0x020)


/*
 * Interrupts.  Those in {} are for AMBA devices
 */
#define IRQ_V2M_WDT		{ (32 + 0) }
#define IRQ_V2M_TIMER0		(32 + 2)
#define IRQ_V2M_TIMER1		(32 + 2)
#define IRQ_V2M_TIMER2		(32 + 3)
#define IRQ_V2M_TIMER3		(32 + 3)
#define IRQ_V2M_RTC		{ (32 + 4) }
#define IRQ_V2M_UART0		{ (32 + 5) }
#define IRQ_V2M_UART1		{ (32 + 6) }
#define IRQ_V2M_UART2		{ (32 + 7) }
#define IRQ_V2M_UART3		{ (32 + 8) }
#define IRQ_V2M_MMCI		{ (32 + 9), (32 + 10) }
#define IRQ_V2M_AACI		{ (32 + 11) }
#define IRQ_V2M_KMI0		{ (32 + 12) }
#define IRQ_V2M_KMI1		{ (32 + 13) }
#define IRQ_V2M_CLCD		{ (32 + 14) }
#define IRQ_V2M_LAN9118		(32 + 15)
#define IRQ_V2M_ISP1761		(32 + 16)
#define IRQ_V2M_PCIE		(32 + 17)


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

#ifndef __ASSEMBLY__
int v2m_cfg_write(u32 devfn, u32 data);
int v2m_cfg_read(u32 devfn, u32 *data);

/*
 * Miscellaneous
 */
#define SYS_MISC_MASTERSITE	(1 << 14)

/*
 * Core tile description
 */
struct ct_id {
	u32 id;
	u32 mask;
};

#define V2M_CT_ID_MASK		0xff000fff

struct ct_desc {
	const struct ct_id	*id_table;
	const char		*name;
	void			(*map_io)(void);
	void			(*init_early)(void);
	void			(*init_irq)(void);
	void			(*timer_init)(void);
	void			(*init_tile)(void);
#ifdef CONFIG_SMP
	void			(*init_cpu_map)(void);
	void			(*smp_enable)(unsigned int);
#endif
};

extern struct ct_desc *ct_desc;

#endif	/* !__ASSEMBLY__ */
#endif
