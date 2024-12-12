#!/bin/sh
gcc -c ascon_core.c -o ascon_core.o -O
gcc ascon.c main.c ascon_core.o -o ascon -O
