#!/bin/sh
acr -p
V=`./configure -qV | cut -d - -f -1`
meson rewrite kwargs set project / version "$V"
vim r2mcp.c
