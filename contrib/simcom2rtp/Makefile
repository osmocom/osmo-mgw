CFLAGS:= -O2 -g -Wall $(shell pkg-config --cflags libosmocore libosmotrau)
LIBS:= $(shell pkg-config --libs libosmocore libosmotrau)

all: osmo-simcom2rtp

osmo-simcom2rtp: g711.o g711_table.o simcom2rtp.o
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) -o $@ -c $^

