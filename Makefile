PROG = $(shell pwd | xargs basename)
OBJECTS = main.o buffer.o xwrap.o
CFLAGS = -O2 -Wall -D_GNU_SOURCE -DNDEBUG -DNOCOLOR -DPROGNAME=\"$(PROG)\" 

all: $(PROG) tcpstat

$(PROG): $(OBJECTS)
	gcc -s -o $@ $(OBJECTS)

tcpstat: tcpstat.o
	gcc -s -o $@ $<

%.o: %.c
	gcc $(CFLAGS) -c -o $@ $<

clean:
	@echo cleaning...
	@rm -f *.o *~ core.*
