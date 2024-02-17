CC = gcc
CFLAGS = -O3 -w -std=c11 -Wall -Wextra -DTIMEKEEPING -DTVHASHOPTIMIZED -DOHBF
LDFLAGS = -lssl -lcrypto -ltomcrypt -lm -lxxhash

HORS_SRC = hors_example.c src/hors.c src/crypto/hash/murmur/*.c src/crypto/hash/xxhash/*.c src/crypto/hash/blake/*.c src/crypto/hash/*.c src/crypto/prng/*.c src/utils/*.c
BFTVMHORS_SRC = bftvmhors_example.c src/ohbf.c src/crypto/hash/wyhash/wyhash.o src/bf.c src/crypto/hash/murmur/*.c src/crypto/hash/xxhash/*.c src/crypto/hash/blake/*.c src/bftvmhors.c src/crypto/hash/*.c src/crypto/prng/*.c src/utils/*.c
TEST_SRC = hash_test.c src/crypto/hash/cityhash/cityhash.o src/crypto/hash/wyhash/wyhash.o src/crypto/hash/murmur/*.c src/crypto/hash/xxhash/*.c src/crypto/hash/blake/*.c src/crypto/hash/*.c src/crypto/prng/*.c src/utils/*.c

## Libxxhaash needs to be installed
install:
	if [ ! -d /usr/include/bftvmhors/ ]; then \
		mkdir /usr/include/bftvmhors/; \
	fi
	cp src/*.h /usr/include/bftvmhors/
	cp src/utils/*.h /usr/include/bftvmhors/

BFTVMHORS:
	if [ ! -d ./target ]; then \
		mkdir ./target; \
	fi
	$(CC) $(BFTVMHORS_SRC) $(CFLAGS) -o target/bftvmhors $(LDFLAGS)
	cp ./config_sample target/config_bftvmhors


HORS:
	if [ ! -d ./target ]; then \
		mkdir ./target; \
	fi
	$(CC) $(HORS_SRC) $(CFLAGS) -o target/hors $(LDFLAGS)
	cp ./config_sample target/config_hors

clean:
	rm -rf ./target ./test
