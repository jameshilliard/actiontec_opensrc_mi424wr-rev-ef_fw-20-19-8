obj-y := setup.o irq.o irq_handler.o time.o

obj-$(CONFIG_SMP)			+= smp.o
obj-$(CONFIG_SIBYTE_TBPROF)		+= bcm1250_tbprof.o
obj-$(CONFIG_SIBYTE_STANDALONE)		+= prom.o
obj-$(CONFIG_SIBYTE_BUS_WATCHER)	+= bus_watcher.o

EXTRA_AFLAGS := $(CFLAGS)
