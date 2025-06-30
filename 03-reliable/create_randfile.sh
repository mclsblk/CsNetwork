#!/bin/bash

dd if=/dev/urandom bs=256K count=3 | base64 > client-input.dat
