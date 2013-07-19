ifneq ($(CONFIG_OF),)
obj-y					+= clk.o dpll.o autoidle.o divider.o \
					   fixed-factor.o gate.o clockdomain.o \
					   composite.o mux.o apll.o
obj-$(CONFIG_SOC_AM33XX)		+= clk-33xx.o
obj-$(CONFIG_ARCH_OMAP4)		+= clk-44xx.o
obj-$(CONFIG_SOC_OMAP5)			+= clk-54xx.o
obj-$(CONFIG_SOC_DRA7XX)		+= clk-7xx.o
endif
