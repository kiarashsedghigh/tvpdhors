CC = gcc
CFLAGS = -O3 -w -std=c11 -Wall -Wextra
LDFLAGS = -lssl -lcrypto -ltomcrypt -lm -lxxhash

HORS_SRC = src/hors.c src/crypto/hash/murmur/*.c src/crypto/hash/xxhash/*.c src/crypto/hash/blake/*.c src/crypto/hash/*.c src/crypto/prng/*.c src/utils/*.c
BFTVMHORS_SRC = src/bf.c src/crypto/hash/murmur/*.c src/crypto/hash/xxhash/*.c src/crypto/hash/blake/*.c src/bftvmhors.c src/crypto/hash/*.c src/crypto/prng/*.c src/utils/*.c
TEST_SRC = hash_test.c src/crypto/hash/murmur/*.c src/crypto/hash/xxhash/*.c src/crypto/hash/blake/*.c src/crypto/hash/*.c src/crypto/prng/*.c src/utils/*.c

HEADER_FILES= bf.h bftvmhors.h hash.h hors.h prng.h types.h

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
	$(CC) $(BFTVMHORS_SRC) $(CFLAGS) -o target/bft $(LDFLAGS)
	cp src/config seed target

HORS:
	if [ ! -d ./target ]; then \
		mkdir ./target; \
	fi
	$(CC) $(HORS_SRC) $(CFLAGS) -o target/hors $(LDFLAGS)
	cp src/config seed target

TEST:
	if [ ! -d ./test ]; then \
		mkdir ./test; \
	fi
	$(CC) $(TEST_SRC) $(CFLAGS) -o test/test $(LDFLAGS)
	cp tprocess.py test


clean:
	rm -rf ./target ./test

#header_clean:
#	rm -rf /usr/include/bftvmhors/{$(HEADER_FILES)}