#!/usr/bin/env bash

gdb -x breakpoints -x showmem.py -p $(pidof exim) 
