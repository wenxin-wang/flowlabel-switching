all: flsw_edge_lwt.o flsw_backbone_xdp.o

flsw_edge_lwt.o: flsw_edge_lwt.c
	clang -O2 -Wall -target bpf -c flsw_edge_lwt.c -o flsw_edge_lwt.o

flsw_backbone_xdp.o: flsw_backbone_xdp.c
	clang -O2 -Wall -target bpf -c flsw_backbone_xdp.c -o flsw_backbone_xdp.o

.PHONY: clean

clean:
	rm -f *.o
