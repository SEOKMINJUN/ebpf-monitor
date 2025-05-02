//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define NAME_SIZE 64
#define MAX_SIZE 128

char __license[] SEC("license") = "Dual MIT/GPL";

struct acceptEvent {
	u32 type;
	u32 pid;
	u32 uid;
	u32 sockfd;
	u16 family;
	u8 addr[14];
	u32 addrlen;
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
	__type(value, struct acceptEvent);
} acceptRingBuffer SEC(".maps");

typedef unsigned short socklen_t;

SEC("kprobe/sys_accept")
int BPF_KPROBE(kprobe_sys_accept, int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	uid_t uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
	struct task_struct* task = bpf_get_current_task_btf();

	struct acceptEvent *event_info;

	event_info = bpf_ringbuf_reserve(&acceptRingBuffer, sizeof(struct acceptEvent), 0);
	if (!event_info) {
		return 0;
	}

	event_info->type = 0;
	event_info->pid = pid;
	event_info->uid = uid;
	event_info->sockfd = sockfd;
	bpf_probe_read(event_info->addr, sizeof(event_info->addr), BPF_CORE_READ(addr, sa_data));

	bpf_ringbuf_submit(event_info, 0);
	bpf_printk("KPROBE ENTRY ACCEPT pid = %d", pid);
	return 0;
}

SEC("kprobe/sys_accept4")
int BPF_KPROBE(kprobe_sys_accept4, int fd, struct sockaddr *upeer_sockaddr, int *upeer_addrlen, int flags)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	uid_t uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
	struct task_struct* task = bpf_get_current_task_btf();

	struct acceptEvent *event_info;

	event_info = bpf_ringbuf_reserve(&acceptRingBuffer, sizeof(struct acceptEvent), 0);
	if (!event_info) {
		return 0;
	}

	event_info->type = 1;
	event_info->pid = pid;
	event_info->uid = uid;
	event_info->sockfd = fd;
	bpf_probe_read(event_info->addr, sizeof(event_info->addr), BPF_CORE_READ(upeer_sockaddr, sa_data));
	bpf_probe_read(&event_info->addrlen, sizeof(event_info->addrlen), upeer_addrlen);

	bpf_ringbuf_submit(event_info, 0);
	bpf_printk("KPROBE ENTRY ACCEPT4 pid = %d, flags = %d", pid, flags);
	return 0;
}


SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(kprobe_tcp_v4_connect, struct sock *sk, struct sockaddr *uaddr, int addr_len)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	uid_t uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
	struct task_struct* task = bpf_get_current_task_btf();

	struct acceptEvent *event_info;

	event_info = bpf_ringbuf_reserve(&acceptRingBuffer, sizeof(struct acceptEvent), 0);
	if (!event_info) {
		return 0;
	}

	event_info->type = 2;
	event_info->pid = pid;
	event_info->uid = uid;
	bpf_probe_read(event_info->addr, sizeof(event_info->addr), BPF_CORE_READ(uaddr, sa_data));

	bpf_ringbuf_submit(event_info, 0);
	bpf_printk("KPROBE ENTRY V4CON pid = %d", pid);
	return 0;
}
