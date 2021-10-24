
CFLAGS = -Wall -g `pkg-config --cflags libosmocore liburing`
LIBS = `pkg-config --libs libosmocore liburing` -lpthread

all: gtp-load-gen simple-gtp-gen

gtp-load-gen: gtp-load-gen.o checksum.o
	$(CC) -o $@ $^ $(LIBS)

simple-gtp-gen: simple-gtp-gen.o
	$(CC) -o $@ $^ $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) -o $@ -c $^


clean:
	@rm gtp-load-gen simple-gtp-gen *.o
