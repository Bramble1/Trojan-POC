#!/bin/bash
gcc -W -g trojan.h trojan.c infect.c -o infect
gcc -no-pie target.c -o target
