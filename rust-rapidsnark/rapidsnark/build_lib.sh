#!/bin/bash

set -e

meson setup --native-file=native-env.ini build --wipe
cd build 
meson compile

