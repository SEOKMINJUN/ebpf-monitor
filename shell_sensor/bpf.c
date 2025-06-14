//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char __license[] SEC("license") = "Dual MIT/GPL";

struct readlineEvent {
	u64 timestamp;
	u32 pid;
	u8 line[80];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__type(value, struct readlineEvent);
} readlineEvents SEC(".maps");

SEC("uretprobe/bash_readline")
int uretprobe_bash_readline(struct pt_regs *ctx) {
	struct readlineEvent event;

	event.timestamp = bpf_ktime_get_ns();
	event.pid = bpf_get_current_pid_tgid();
	bpf_probe_read(&event.line, sizeof(event.line), (void *)PT_REGS_RC(ctx));

	bpf_perf_event_output(ctx, &readlineEvents, BPF_F_CURRENT_CPU, &event, sizeof(event));

	return 0;
}