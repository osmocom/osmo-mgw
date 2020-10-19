CFLAGS=-g -Wall $(shell pkg-config --cflags libosmocore libosmoctrl libosmo-netif liburing)
LIBS=-lpthread $(shell pkg-config --libs libosmocore libosmoctrl libosmo-netif liburing)

rtp-load-gen: rtp-load-gen.o rtp_provider.o rtp_provider_static.o ctrl_if.o
	$(CC) -o $@ $^ $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) -o $@ -c $^

clean:
	@rm rtp-load-gen *.o
