SRC_TARGETS=all clean install user-install uninstall user-uninstall

$(SRC_TARGETS): src/Makefile
	$(MAKE) -C src $@

src/Makefile:
	./configure

.PHONY: $(SRC_TARGETS) help

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
