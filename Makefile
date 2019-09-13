CC = /usr/bin/gcc
CFLAGS = -Wall -Wextra -g -O3 -fomit-frame-pointer -march=native
NISTFLAGS = -O3 -fomit-frame-pointer -march=native -fPIC -no-pie
NOOPTNISTFLAGS = -fomit-frame-pointer -march=native -fPIC -no-pie

all:	GENU32 GCM

GENU32: 
	$(CC) -o gen gen.c -lcrypto
GCM: 
	$(CC) -o gcm gcm.c -lcrypto

.PHONY: clean

clean:
	-rm test
	-rm data/*

