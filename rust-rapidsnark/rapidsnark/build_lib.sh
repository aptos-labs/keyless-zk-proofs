#!/bin/bash

set -e

rm -rf build
meson setup --native-file=native-env.ini build 
cd build 
meson compile

