#!/bin/bash
gcc -W -g trojan.h trojan.c infect.c -o infect
gcc -no-pie target.c -o target

nasm -f bin payload.asm -o payload.bin
