#ifndef ARM_PLAT_LOCALTIMER_H
#define ARM_PLAT_LOCALTIMER_H

#include <linux/clockchips.h>

void versatile_local_timer_setup(struct clock_event_device *evt);
void versatile_local_timer_init(void __iomem *base);

#endif
