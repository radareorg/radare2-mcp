CC?= gcc
TARGET = r2mcp
CFLAGS = -Wall -Wextra -g
PIC_CFLAGS ?= -fPIC
SHARED_LDFLAGS ?= -shared

# AddressSanitizer build
asan: CFLAGS += -fsanitize=address -fsanitize=undefined -g3 -O1
asan: LDFLAGS += -fsanitize=address -fsanitize=undefined
asan: clean $(TARGET)
	@echo "✓ AddressSanitizer build complete."
PKGCONFIG = pkg-config
INSTALL_DIR?=install -d
R2_LIBEXT=$(shell r2 -H R2_LIBEXT)
INSTALL_PROGRAM?=install -m 755
INSTALL_DATA?=install -m 644
PREFIX?=/usr/local
R2PM_BINDIR?=$(shell r2pm -H R2PM_BINDIR)
R2PM_PLUGDIR?=$(shell r2pm -H R2PM_PLUGDIR)

COMMON_SRC = r2mcp.c
COMMON_SRC += readbuffer.c
COMMON_SRC += tools.c
COMMON_SRC += dsltest.c
COMMON_SRC += prompts.c
COMMON_SRC += jsonrpc.c
COMMON_SRC += validation.c
COMMON_SRC += sessions.c
COMMON_SRC += compat.c
BIN_SRC = main.c $(COMMON_SRC)
PLUGIN_SRC = plugin.c $(COMMON_SRC)
INC = utils.inc.c
INC += r2api.inc.c
INC += path.inc.c
INC += curl.inc.c
BIN_OBJS := $(BIN_SRC:.c=.o)
PLUGIN_OBJS := $(PLUGIN_SRC:.c=.pic.o)

# Detect OS-specific settings
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
    # macOS specific include paths
    CFLAGS += -I/usr/local/include/libr -I/usr/local/include
    CFLAGS += -I$(shell brew --prefix)/include
    SHARED_LDFLAGS = -dynamiclib
endif

# Get compiler flags from pkg-config
R2_CFLAGS = $(shell $(PKGCONFIG) --cflags r_core)
R2_LDFLAGS = $(shell $(PKGCONFIG) --libs r_core)

CFLAGS += $(R2_CFLAGS)
LDFLAGS = $(R2_LDFLAGS)

.PHONY: all clean check_deps help install uninstall user-install user-uninstall

LIBTARGET=libcore_$(TARGET).$(R2_LIBEXT)
all: check_deps $(TARGET) $(LIBTARGET)

check_deps:
	@echo "Checking dependencies..."
	@which $(PKGCONFIG) > /dev/null || (echo "pkg-config not found. Please install it."; exit 1)
	@$(PKGCONFIG) --exists r_core || (echo "radare2 development files not found."; exit 1)
	@echo "✓ All dependencies are satisfied."

$(TARGET): $(BIN_OBJS) $(INC)
	@echo "Building R2 MCP server..."
	$(CC) $(CFLAGS) -o $@ $(BIN_OBJS) $(LDFLAGS)
	@echo "✓ Server built successfully."

$(LIBTARGET): $(PLUGIN_OBJS) $(INC)
	$(CC) $(SHARED_LDFLAGS) -o $(LIBTARGET) $(PLUGIN_OBJS) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

%.pic.o: %.c
	$(CC) $(CFLAGS) $(PIC_CFLAGS) -c -o $@ $<

clean:
	rm -f $(TARGET) $(LIBTARGET) $(BIN_OBJS) $(PLUGIN_OBJS)
	-rm -rf r2mcp.dSYM

mrproper: clean
	rm -f Makefile

install: all
	$(INSTALL_DIR) $(DESTDIR)/$(PREFIX)/bin
	$(INSTALL_PROGRAM) $(TARGET) $(DESTDIR)/$(PREFIX)/bin/r2mcp
	$(INSTALL_DIR) $(DESTDIR)/$(PREFIX)/share/man/man1
	$(INSTALL_DATA) ../doc/r2mcp.1 $(DESTDIR)/$(PREFIX)/share/man/man1/r2mcp.1

uninstall:
	rm -f $(DESTDIR)/$(PREFIX)/bin/r2mcp
	rm -f $(DESTDIR)/$(PREFIX)/share/man/man1/r2mcp.1

user-install: all
	$(INSTALL_DIR) $(R2PM_BINDIR)
	$(INSTALL_PROGRAM) $(TARGET) $(R2PM_BINDIR)/r2mcp
	$(INSTALL_PROGRAM) $(LIBTARGET) $(R2PM_PLUGDIR)
	$(INSTALL_DIR) $(HOME)/.config/r2mcp/prompts
	cp -f ../prompts/*.r2ai.md $(HOME)/.config/r2mcp/prompts/

doc:
	cat INSTALL.md

user-uninstall:
	rm -f $(R2PM_BINDIR)/r2mcp
	rm -f $(R2PM_PLUGDIR)/$(LIBTARGET)
	rm -rf $(HOME)/.config/r2mcp/prompts

indent fmt:
	clang-format-radare2 *.c

help:
	@echo "Available targets:"
	@echo "  all            - Build the server (default)"
	@echo "  asan           - Build with AddressSanitizer (ASAN)"
	@echo "  check_deps     - Check for required dependencies"
	@echo "  clean          - Remove built binaries"
	@echo "  install        - Install the server to /usr/local/bin"
	@echo "  uninstall      - Install the server to /usr/local/bin"
	@echo "  user-install   - Install the server to /usr/local/bin"
	@echo "  user-uninstall - Install the server to /usr/local/bin"
	@echo "  help           - Display this help message"
	@echo
	@echo "Usage: make [target]"
