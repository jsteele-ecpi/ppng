#!/bin/sh

set -xe

CC=gcc
CFLAGS="-Wall -Wextra"

$CC $CFLAGS -o ppng ppng.c
