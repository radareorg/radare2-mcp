CC ?= gcc
PKGCONFIG = pkg-config
R2_CFLAGS = $(shell $(PKGCONFIG) --cflags r_util)
R2_LDFLAGS = $(shell $(PKGCONFIG) --libs r_util r_socket r_cons)
R2PM_BINDIR=$(shell r2pm -H R2PM_BINDIR)
INSTALL_DIR ?= install -d
INSTALL_PROGRAM ?= install -m 755
PREFIX ?= /usr/local

TARGET = r2mcp-svc

all: $(TARGET)

$(TARGET): r2mcp-svc.c
	$(CC) $(R2_CFLAGS) -Wall -Wextra -o $@ $< $(R2_LDFLAGS)

clean:
	rm -f $(TARGET)

install: all
	$(INSTALL_DIR) $(DESTDIR)/$(PREFIX)/bin
	$(INSTALL_PROGRAM) $(TARGET) $(DESTDIR)/$(PREFIX)/bin/$(TARGET)

uninstall:
	rm -f $(DESTDIR)/$(PREFIX)/bin/$(TARGET)

user-install:
	$(INSTALL_DIR) $(DESTDIR)/$(R2PM_BINDIR)
	$(INSTALL_PROGRAM) $(TARGET) $(DESTDIR)/$(R2PM_BINDIR)/$(TARGET)

user-uninstall:
	rm -f $(DESTDIR)/$(R2PM_BINDIR)/$(TARGET)

.PHONY: clean install uninstall
