#!/bin/bash
gcc test.c -Llib -lsodium -Iinclude -lX25519 -Lbuild/lib/ -o x25519_test
