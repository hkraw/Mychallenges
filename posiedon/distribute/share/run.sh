#!/bin/sh
./ynetd -p 10111 "LD_PRELOAD=./libc-2.32.so ./cards"
