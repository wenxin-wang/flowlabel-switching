all:
	$(MAKE) -C bpf
	$(MAKE) -C tools

install:
	$(MAKE) -C bpf install
	$(MAKE) -C tools install

uninstall:
	$(MAKE) -C bpf uninstall
	$(MAKE) -C tools uninstall

.PHONY: all install uninstall
