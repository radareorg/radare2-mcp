CC = gcc
CFLAGS = -I/usr/local/include/libr -Wall -Wextra
LDFLAGS = -L/usr/local/lib -lr_socket -lr_util

TARGET = r2mcp-svc

all: $(TARGET)

$(TARGET): r2mcp-svc.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TARGET)

.PHONY: clean
