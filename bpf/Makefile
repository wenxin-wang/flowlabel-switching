PKG_CONFIG ?= pkg-config
INSTALL ?= install
RM ?= rm

PREFIX ?= /usr/local

SHARED_DIR ?= $(DESTDIR)$(PREFIX)/share/flsw

all: flsw_ingress_lwt.o flsw_backbone_xdp.o

flsw_ingress_lwt.o: flsw_ingress_lwt.c
	clang -O2 -Wall -target bpf -c flsw_ingress_lwt.c -o flsw_ingress_lwt.o

flsw_backbone_xdp.o: flsw_backbone_xdp.c
	clang -O2 -Wall -target bpf -c flsw_backbone_xdp.c -o flsw_backbone_xdp.o

install: flsw_ingress_lwt.o flsw_backbone_xdp.o
	$(INSTALL) -d -m 755 $(SHARED_DIR)
	$(INSTALL) -m 644 flsw_ingress_lwt.o $(SHARED_DIR)/flsw_ingress_lwt.o
	$(INSTALL) -m 644 flsw_backbone_xdp.o $(SHARED_DIR)/flsw_backbone_xdp.o

uninstall:
	$(RM) $(SHARED_DIR)/flsw_ingress_lwt.o $(SHARED_DIR)/flsw_backbone_xdp.o

.PHONY: clean install uninstall

clean:
	rm -f *.o
