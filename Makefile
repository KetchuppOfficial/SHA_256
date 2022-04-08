CC = gcc
CFLAGS = -c -Wall -Werror -Wextra

all: sha_256

sha_256: main.o sha_256.o
	$(CC) Objects/main.o Objects/sha_256.o -o Objects/sha_256.out

main.o: main.c
	$(CC) $(CFLAGS) main.c -o Objects/main.o

sha_256.o: sha_256.c
	$(CC) $(CFLAGS) sha_256.c -o Objects/sha_256.o

run:
	Objects/sha_256.out

valgrind:
	valgrind -s Objects/sha_256.out

lib:
	ar r sha_256.a Objects/sha_256.o

clean:
	rm Objects/main.o
	rm Objects/sha_256.o
	rm Objects/sha_256.out

