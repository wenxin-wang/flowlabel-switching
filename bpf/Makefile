all: flsw_edge_lwt.o

flsw_edge_lwt.o: flsw_edge_lwt.c
	clang -O2 -Wall -target bpf -c flsw_edge_lwt.c -o flsw_edge_lwt.o

.PHONY: clean

clean:
	rm -f *.o
