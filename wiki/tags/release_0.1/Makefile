CC = gcc
LIBS = /usr/lib/libpcap.a -lpthread
CFLAGS = -Wall -g

.PHONY: all
all: zruijie

zruijie	: md5.o zruijie.o blog.o main.o
	$(CC) $(CFLAGS) -o $@ md5.o zruijie.o blog.o main.o $(LIBS)

main.o	: main.c
	$(CC) $(CFLAGS) -c $<

md5.o	: md5.c md5.h
	$(CC) $(CFLAGS) -c $<

zruijie.o : zruijie.c zruijie.h
	$(CC) $(CFLAGS) -c $<

blog.o	: blog.c blog.h
	$(CC) $(CFLAGS) -c $<
	
clean :
	rm -v *.o
