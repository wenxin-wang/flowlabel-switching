all: flsw_lwt.o

flsw_lwt.o: flsw_lwt.c
	clang -O2 -Wall -target bpf -c flsw_lwt.c -o flsw_lwt.o

.PHONY: clean

clean:
	rm -f *.o
