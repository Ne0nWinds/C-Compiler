#!/usr/bin/env bash

# Usage: ./build.sh 
#        ./build.sh unittests

MODE="$1"

CFLAGS="-Wno-c99-designator -Wno-switch -fno-exceptions -fno-operator-names"

if [[ "$MODE" == "--unit-tests" ]]; then
	CFLAGS="$CFLAGS -DRUN_UNIT_TESTS=1"
fi

clang++ $CFLAGS -g -std=c++20 main.cpp 
