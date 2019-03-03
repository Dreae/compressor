CC = clang

objects += src/compressor.o src/compressor_filter_user.o

libbpf_objects += libbpf/src/bpf.o libbpf/src/btf.o libbpf/src/libbpf_errno.o libbpf/src/libbpf_probes.o
libbpf_objects += libbpf/src/libbpf.o libbpf/src/netlink.o libbpf/src/nlattr.o libbpf/src/str_error.o

CFLAGS += -Ilibbpf/src
LDFLAGS += -lconfig -lelf

all: compressor compressor_xdb
compressor: libbpf $(objects)
	clang $(LDFLAGS) -o compressor $(libbpf_objects) $(objects)
compressor_xdb: src/compressor_filter_kern.o
	clang -Wall -Wextra -O2 -emit-llvm -c src/compressor_filter_kern.c -o src/compressor_filter_kern.bc
	llc -march=bpf -filetype=obj src/compressor_filter_kern.bc -o src/compressor_filter_kern.o
libbpf:
	$(MAKE) -C libbpf/src

.PHONY: libbpf all
.DEFAULT: all