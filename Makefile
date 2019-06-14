# Copyright (C) 2019 dreae
# 
# This file is part of compressor.
# 
# compressor is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# 
# compressor is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with compressor.  If not, see <http://www.gnu.org/licenses/>.

CC = clang

objects += src/compressor.o src/compressor_filter_user.o src/config.o src/bpf_load.o src/compressor_cache_user.o
objects += src/compressor_cache_seed.o src/cockpit_port.o

libbpf_objects += libbpf/src/bpf.o libbpf/src/btf.o libbpf/src/libbpf_errno.o libbpf/src/libbpf_probes.o
libbpf_objects += libbpf/src/libbpf.o libbpf/src/netlink.o libbpf/src/nlattr.o libbpf/src/str_error.o

CFLAGS += -Ilibbpf/src -g -O2 -Wall -Werror
LDFLAGS += -lconfig -lpthread -lelf -lhiredis -levent

all: compressor compressor_filter
compressor: libbpf $(objects)
	clang $(LDFLAGS) -o compressor $(libbpf_objects) $(objects)
compressor_filter: src/compressor_filter_kern.o
	clang -D__BPF__ -Wall -Wextra -O2 -emit-llvm -c src/compressor_filter_kern.c -o src/compressor_filter_kern.bc
	llc -march=bpf -filetype=obj src/compressor_filter_kern.bc -o src/compressor_filter_kern.o
libbpf:
	$(MAKE) -C libbpf/src
clean:
	$(MAKE) -C libbpf/src clean
	rm -f src/*.o src/*.bc
	rm -f compressor
install:
	mkdir -p /etc/compressor
	cp -n compressor.example.conf /etc/compressor/compressor.conf
	cp src/compressor_filter_kern.o /etc/compressor/compressor_filter_kern.o
	cp compressor /usr/bin/compressor
	cp -n systemd/compressor.service /etc/systemd/system/

.PHONY: libbpf all
.DEFAULT: all