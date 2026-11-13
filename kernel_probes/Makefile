CLANG ?= clang
CFLAGS ?= -O2 -g -target bpf -D__TARGET_ARCH_x86
PROBE := probes.bpf.c
COMMON := ../common/event_defs.h

.PHONY: check lint clean

check:
	@test -f $(COMMON)
	@if test -d /usr/include/bcc; then \
		$(CLANG) $(CFLAGS) -fsyntax-only -I../common $(PROBE); \
	else \
		printf '%s\n' 'BCC headers unavailable; running contract checks only'; \
		grep -q 'BPF_PERF_OUTPUT(events)' $(PROBE); \
		grep -q 'TRACEPOINT_PROBE(syscalls, sys_enter_write)' $(PROBE); \
		grep -q 'TRACEPOINT_PROBE(syscalls, sys_enter_renameat2)' $(PROBE); \
		grep -q 'TRACEPOINT_PROBE(syscalls, sys_enter_unlinkat)' $(PROBE); \
		grep -q 'TRACEPOINT_PROBE(syscalls, sys_enter_close)' $(PROBE); \
	fi

lint:
	@python3 -m py_compile probe_loader.py tests/test_stream.py

clean:
	@rm -f probes.bpf.o
