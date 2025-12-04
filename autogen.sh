#!/bin/sh
[ -z "${EDITOR}" ] && EDITOR=vim
acr -p
V=`./configure -qV | cut -d - -f -1`
meson rewrite kwargs set project / version "$V"
${EDITOR} src/r2mcp.h
${EDITOR} src/r2mcp.c
