CC?= gcc
TARGET = r2mcp
SRC = r2mcp.c
CFLAGS = -Wall -Wextra -g
PKGCONFIG = pkg-config
INSTALL_DIR?=install -d
INSTALL_PROGRAM?=install -m 755
PREFIX?=/usr/local
R2PM_BINDIR?=$(shell r2pm -H R2PM_BINDIR)

# Detect OS-specific settings
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
    # macOS specific include paths
    CFLAGS += -I/usr/local/include/libr -I/usr/local/include
    CFLAGS += -I$(shell brew --prefix)/include
endif

# Get compiler flags from pkg-config
R2_CFLAGS = $(shell $(PKGCONFIG) --cflags r_core)
R2_LDFLAGS = $(shell $(PKGCONFIG) --libs r_core)

CFLAGS += $(R2_CFLAGS)
LDFLAGS = $(R2_LDFLAGS)

.PHONY: all clean check_deps help install uninstall user-install user-uninstall

all: check_deps $(TARGET)

check_deps:
	@echo "Checking dependencies..."
	@which $(PKGCONFIG) > /dev/null || (echo "pkg-config not found. Please install it."; exit 1)
	@$(PKGCONFIG) --exists r_core || (echo "radare2 development files not found."; exit 1)
	@echo "✓ All dependencies are satisfied."

$(TARGET): $(SRC)
	@echo "Building R2 MCP server..."
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)
	@echo "✓ Server built successfully."

clean:
	rm -f $(TARGET)

install: all
	$(INSTALL_DIR) $(DESTDIR)/$(PREFIX)/bin
	$(INSTALL_PROGRAM) $(TARGET) $(DESTDIR)/$(PREFIX)/bin/r2mcp

uninstall:
	rm -f $(DESTDIR)/$(PREFIX)/bin/r2mcp

user-install: all
	$(INSTALL_DIR) $(R2PM_BINDIR)
	$(INSTALL_PROGRAM) $(TARGET) $(R2PM_BINDIR)/r2mcp

user-uninstall:
	rm -f $(R2_BINDIR)/bin/r2mcp

help:
	@echo "Available targets:"
	@echo "  all            - Build the server (default)"
	@echo "  check_deps     - Check for required dependencies"
	@echo "  clean          - Remove built binaries"
	@echo "  install        - Install the server to /usr/local/bin"
	@echo "  uninstall      - Install the server to /usr/local/bin"
	@echo "  user-install   - Install the server to /usr/local/bin"
	@echo "  user-uninstall - Install the server to /usr/local/bin"
	@echo "  help           - Display this help message"
	@echo
	@echo "Usage: make [target]"
