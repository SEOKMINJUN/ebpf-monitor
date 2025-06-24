//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char __license[] SEC("license") = "Dual MIT/GPL";

struct readlineEvent {
	u64 timestamp;
	u32 pid;
	u32 uid;
	u8 comm[TASK_COMM_LEN];
	u8 line[80];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__type(value, struct readlineEvent);
} readlineEvents SEC(".maps");

SEC("uretprobe//bin/bash:readline")
int BPF_KRETPROBE(uretprobe_bash_readline, const void *ret) {
	struct readlineEvent event;

	event.timestamp = bpf_ktime_get_ns();
	event.pid = bpf_get_current_pid_tgid() >> 32;
	event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
 	bpf_get_current_comm(&event.comm, sizeof(event.comm));
	bpf_probe_read(&event.line, sizeof(event.line), ret);

	bpf_perf_event_output(ctx, &readlineEvents, BPF_F_CURRENT_CPU, &event, sizeof(event));

	bpf_printk("bash_readline\n");

	return 0;
}