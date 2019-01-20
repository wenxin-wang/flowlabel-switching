PKG_CONFIG ?= pkg-config
INSTALL ?= install

PREFIX ?= /usr/local

LIBBCC_CFLAGS := $(shell $(PKG_CONFIG) --cflags libbcc 2>/dev/null)
LIBBCC_LDLIBS := $(shell $(PKG_CONFIG) --libs libbcc 2>/dev/null || echo -lbcc)
CFLAGS += $(LIBBCC_CFLAGS)
LDLIBS += $(LIBBCC_LDLIBS)

all: flswctl

flswctl: flswctl.o edge_main.o edge_set.o edge_show.o edge_flush.o addr_utils.o bpf_label.o

.PHONY: clean

clean:
	rm -f *.o
