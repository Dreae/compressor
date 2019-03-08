CC = clang

objects += src/compressor.o src/compressor_filter_user.o src/config.o src/bpf_load.o src/compressor_cache_user.o

libbpf_objects += libbpf/src/bpf.o libbpf/src/btf.o libbpf/src/libbpf_errno.o libbpf/src/libbpf_probes.o
libbpf_objects += libbpf/src/libbpf.o libbpf/src/netlink.o libbpf/src/nlattr.o libbpf/src/str_error.o

CFLAGS += -Ilibbpf/src
LDFLAGS += -lconfig -lelf

all: compressor compressor_filter compressor_cache
compressor: libbpf $(objects)
	clang $(LDFLAGS) -o compressor $(libbpf_objects) $(objects)
compressor_filter: src/compressor_filter_kern.o
	clang -Wall -Wextra -O2 -emit-llvm -c src/compressor_filter_kern.c -o src/compressor_filter_kern.bc
	llc -march=bpf -filetype=obj src/compressor_filter_kern.bc -o src/compressor_filter_kern.o
compressor_cache: src/compressor_cache_kern.o
	clang -Wall -Wextra -O2 -emit-llvm -c src/compressor_cache_kern.c -o src/compressor_cache_kern.bc
	llc -march=bpf -filetype=obj src/compressor_cache_kern.bc -o src/compressor_cache_kern.o
libbpf:
	$(MAKE) -C libbpf/src
clean:
	$(MAKE) -C libbpf/src clean
	rm -f src/*.o src/*.bc
	rm -f compressor
install:
	mkdir -p /etc/compressor
	cp compressor.example.conf /etc/compressor/compressor.conf
	cp src/compressor_filter_kern.o /etc/compressor/compressor_filter_kern.o
	cp src/compressor_cache_kern.o /etc/compressor/compressor_cache_kern.o

.PHONY: libbpf all
.DEFAULT: all