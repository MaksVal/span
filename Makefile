SRCS   = span.c
OBJS   = $(SRCS:.c=.o)
CC = gcc
obj-m += span.o
#CFLAGS_span.o := -DDEBUG

all:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	$(RM) Module.markers modules.order
