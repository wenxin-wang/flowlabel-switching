PKG_CONFIG ?= pkg-config
INSTALL ?= install

PREFIX ?= /usr/local

LIBBCC_CFLAGS := $(shell $(PKG_CONFIG) --cflags libbcc 2>/dev/null)
LIBBCC_LDLIBS := $(shell $(PKG_CONFIG) --libs libbcc 2>/dev/null || echo -lbcc)
CFLAGS += $(LIBBCC_CFLAGS)
LDLIBS += $(LIBBCC_LDLIBS)

all: flswctl

flswctl: flswctl.o ingress_main.o ingress_set.o ingress_show.o ingress_flush.o \
backbone_main.o backbone_set.o backbone_show.o backbone_flush.o addr_utils.o

install: flswctl
	$(INSTALL) -m 755 flswctl $(DESTDIR)$(PREFIX)/bin/flswctl

uninstall:
	$(RM) $(DESTDIR)$(PREFIX)/bin/flswctl

.PHONY: clean install uninstall

clean:
	rm -f *.o
