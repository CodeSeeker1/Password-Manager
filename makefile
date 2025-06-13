TITLE = "Password Manager makefile 1.00 250521"

CC = gcc 
CFLAGS = -Wall -std=c99

manager:
	@echo $(TITLE)
	$(CC) pmanager.c -o manager -lsodium

#separate complication
pmanager.o: pmanager.c pmanager.h
	$(CC) -c pmanager.c $(CFLAGS)

PHONY: clean

clean:
		rm -f manager  pmanager.o
