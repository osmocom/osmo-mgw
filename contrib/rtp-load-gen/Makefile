CFLAGS=-g -Wall $(shell pkg-config --cflags libosmocore libosmo-netif liburing)
LIBS=-lpthread $(shell pkg-config --libs libosmocore libosmo-netif liburing)

rtp-load-gen: rtp-load-gen.o
	$(CC) -o $@ $^ $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) -o $@ -c $^
