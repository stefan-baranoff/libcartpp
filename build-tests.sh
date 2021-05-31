#!/bin/bash
g++ -fsanitize=address,leak,undefined -O0 -g -std=gnu++17 tests/cart_test.cpp -o tests/cart_test -I . -I /usr/include/jsoncpp/ -L /usr/lib64 -lgtest -lssl -lcrypto -lz -ljsoncpp
