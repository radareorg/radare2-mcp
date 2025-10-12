SRC_TARGETS=all clean install user-install uninstall user-uninstall

$(SRC_TARGETS): src/Makefile
	$(MAKE) -C src $@
	$(MAKE) -C svc $@

format fmt indent:
	clang-format-radare2 src/*.c svc/*.c
	#clang-format -i src/*.c svc/*.c

src/Makefile:
	./configure

doc:
	cat INSTALL.md

.PHONY: $(SRC_TARGETS) help doc
