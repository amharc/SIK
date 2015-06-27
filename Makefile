EXECS=opoznienia

CFLAGS=-Wall -Wextra -Werror -pedantic -O3 -std=c11 -pthread -fstack-protector-all -fpie -fno-strict-aliasing -D_FORTIFY_SOURCE=2 $(shell pkg-config --cflags libevent_pthreads)
LDFLAGS=$(shell pkg-config --libs libevent_pthreads) -lpthread -fpie
SOURCES=$(wildcard *.c)
DEPENDS=$(patsubst %.c,.%.depends,$(SOURCES))
OBJECTS=$(patsubst %.c,%.o,$(SOURCES))

all: $(EXECS)

opoznienia: opoznienia.o $(OBJECTS)

.%.depends: %.c
	$(CC) $(CFLAGS) -MM $< -o $@

.PHONY: clean
clean:
	rm -f *.o $(EXECS) $(DEPENDS)

-include $(DEPENDS)
