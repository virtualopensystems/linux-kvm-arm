ifeq ($(CONFIG_VEXPRESS_ORIGINAL_MEMORY_MAP),y)
   zreladdr-y	+= 0x60008000
params_phys-y	:= 0x60000100
initrd_phys-y	:= 0x60800000
else
ifeq ($(CONFIG_VEXPRESS_EXTENDED_MEMORY_MAP),y)
   zreladdr-y	+= 0x80008000
params_phys-y	:= 0x80000100
initrd_phys-y	:= 0x80800000
endif
endif
