CC := gcc

all:infect payload

infect: trojan.c infect.c
	$(CC) -W -g trojan.c infect.c -o infect

payload:
	nasm -f bin payload.asm -o payload.bin

.PHONY: clean
clean:
	rm -f payload.bin infect

