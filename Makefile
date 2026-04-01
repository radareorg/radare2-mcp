SRC_TARGETS=all clean install user-install uninstall user-uninstall asan
R2MCP_VERSION=$(shell awk '/^VERSION[[:space:]]+/ { print $$2; exit }' configure.acr)

$(SRC_TARGETS): src/Makefile
	$(MAKE) -C src $@
	$(MAKE) -C svc $@

test:
	bash test.sh
	bash test2.sh

format fmt indent:
	clang-format-radare2 src/*.c svc/*.c src/*.h
	#clang-format -i src/*.c svc/*.c

src/Makefile:
	./configure

doc:
	cat INSTALL.md

codex-plugin:
	VERSION="$(if $(strip $(VERSION)),$(VERSION),$(R2MCP_VERSION))" sh dist/scripts/package-codex-plugin.sh

codex-plugin-install:
	sh dist/scripts/install-codex-plugin.sh

codex-plugin-uninstall:
	sh dist/scripts/uninstall-codex-plugin.sh

.PHONY: $(SRC_TARGETS) help doc test codex-plugin codex-plugin-install codex-plugin-uninstall
