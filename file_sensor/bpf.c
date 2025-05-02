//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>


#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

#define MAX_SIZE 128

char __license[] SEC("license") = "Dual MIT/GPL";

struct fileOpenEvent {
	u32 pid;
	u32 uid;
	u8 name[MAX_SIZE];
	u32 flags;
	u16 mode;
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
	__type(value, struct fileOpenEvent);
} events SEC(".maps");


//ProcessCreate
SEC("kprobe/do_sys_openat2")
int BPF_KPROBE(kprobe_do_sys_openat2, int dfd, const char *filename, struct open_how *how)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	uid_t uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
	u64 flags = BPF_CORE_READ(how, flags);
	u64 mode = BPF_CORE_READ(how, mode);
    // bpf_printk("KPROBE ENTRY OPEN: pid = %d, filename = %s, flag = %d, mode = %d\n", pid, filename, flags, mode);

	struct fileOpenEvent *task_info;

	task_info = bpf_ringbuf_reserve(&events, sizeof(struct fileOpenEvent), 0);
	if (!task_info) {
		return 0;
	}

	task_info->pid = pid;
	task_info->uid = uid;
	bpf_probe_read_str(task_info->name, sizeof(task_info->name), filename);
	task_info->flags = flags;
	task_info->mode = mode;
	
	bpf_ringbuf_submit(task_info, 0);
    return 0;
}