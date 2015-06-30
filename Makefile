CC=gcc
CFLAGS=-g -Wall 
LIBS=-lpcap
mydump: util.o mydump.o
	$(CC) -o mydump util.o mydump.o $(CFLAGS) $(LIBS)


.PHONY: clean
clean:
	rm -f *.o mydump