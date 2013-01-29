void __sp804_clocksource_and_sched_clock_init(void __iomem *,
					      const char *, struct clk *, int);

static inline void sp804_clocksource_init(void __iomem *base, const char *name,
					  struct clk *clk)
{
	__sp804_clocksource_and_sched_clock_init(base, name, clk, 0);
}

static inline void sp804_clocksource_and_sched_clock_init(void __iomem *base,
							  const char *name,
							  struct clk *clk)
{
	__sp804_clocksource_and_sched_clock_init(base, name, clk, 1);
}

void sp804_clockevents_init(void __iomem *, unsigned int, const char *,
			    struct clk *);
