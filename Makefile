PROG = $(shell pwd | xargs basename)
PROG_STAT = $(PROG)_stat
OBJECTS = main.o buffer.o xwrap.o
CFLAGS = -O2 -Wall -D_GNU_SOURCE -DNDEBUG -DNOCOLOR -DPROGNAME=\"$(PROG)\" 

all: $(PROG) $(PROG_STAT)

$(PROG): $(OBJECTS)
	gcc -s -o $@ $(OBJECTS)

$(PROG)_stat: stat.o
	gcc -s -o $@ $<

%.o: %.c
	gcc $(CFLAGS) -c -o $@ $<

clean:
	@echo cleaning...
	@rm -f *.o *~ core.*
