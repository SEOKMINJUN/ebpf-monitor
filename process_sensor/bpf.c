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

struct processCreateEvent {
	u32 pid;
	u32 uid;
	u8 name[MAX_SIZE];
	u32 len;
	u8 comm[TASK_COMM_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
	__type(value, struct processCreateEvent);
} events SEC(".maps");


//ProcessCreate
// TODO: Fix filename is invalid
SEC("kprobe/sys_execve")
// int BPF_KPROBE(kprobe_sys_execve, const char *filename, const char *const *argv, const char *const *envp)
int kprobe_sys_execve(struct pt_regs *ctx)
{
	char filename[256];
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	uid_t uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
	

	struct processCreateEvent *task_info;

	task_info = bpf_ringbuf_reserve(&events, sizeof(struct processCreateEvent), 0);
	if (!task_info) {
		return 0;
	}

	task_info->pid = pid;
	task_info->uid = uid;
	task_info->len = bpf_probe_read_user_str(task_info->name, sizeof(task_info->name), (const char*)PT_REGS_PARM3(ctx));
	bpf_get_current_comm(&task_info->comm, sizeof(task_info->comm));
	bpf_printk("KPROBE ENTRY EXECVE pid = %d, uid = %d, fname = %s\n", pid, uid, (const char*)PT_REGS_PARM2(ctx));

	
	bpf_ringbuf_submit(task_info, 0);
    return 0;
}