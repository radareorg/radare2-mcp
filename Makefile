SRC_TARGETS=all clean install user-install uninstall user-uninstall

$(SRC_TARGETS): src/Makefile
	$(MAKE) -C src $@

src/Makefile:
	./configure

.PHONY: $(SRC_TARGETS) help
