//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define NAME_SIZE 64
#define MAX_SIZE 128

char __license[] SEC("license") = "Dual MIT/GPL";

struct acceptEvent {
	u64 timestamp;
	u32 pid;
	u32 uid;
	u32 sockfd;
	u16 family;
	u8 addr[14];
	u32 src_addr;
	u16 src_port;
	u32 dest_addr;
	u16 dest_port;
	u32 addrlen;
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
	__type(value, struct acceptEvent);
} acceptRingBuffer SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, pid_t);
	__type(value, void*);
} tcp_socket_hashmap SEC(".maps");

typedef unsigned short socklen_t;


SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(kprobe_tcp_v4_connect, struct sock *sk, struct sockaddr *uaddr, int addr_len)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	bpf_map_update_elem(&tcp_socket_hashmap, &pid, &sk, BPF_ANY);

#ifdef BPF_DEBUG
	bpf_printk("KPROBE ENTRY V4CON pid = %d", pid);
#endif
	return 0;
}

SEC("kretprobe/tcp_v4_connect")
int kretprobe_tcp_v4_connect(struct pt_regs* ctx)
{
	int ret = PT_REGS_RC(ctx);
	uid_t uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	struct sock **sk;
	sk = bpf_map_lookup_elem(&tcp_socket_hashmap, &pid);
	if(sk == NULL) return 0;
	bpf_map_delete_elem(&tcp_socket_hashmap, &pid);
	
	if(ret != 0) return 0;
	struct acceptEvent *event_info;

	event_info = bpf_ringbuf_reserve(&acceptRingBuffer, sizeof(struct acceptEvent), 0);
	if (!event_info) {
		return 0;
	}

	event_info->timestamp = bpf_ktime_get_ns();
	event_info->pid = pid;
	event_info->uid = uid;
	event_info->family = BPF_CORE_READ(*sk, __sk_common.skc_family);
	event_info->dest_addr = BPF_CORE_READ(*sk, __sk_common.skc_daddr);
	event_info->dest_port = BPF_CORE_READ(*sk, __sk_common.skc_dport);
	event_info->src_addr = BPF_CORE_READ(*sk, __sk_common.skc_rcv_saddr);
	event_info->src_port = BPF_CORE_READ(*sk, __sk_common.skc_num);
	
	bpf_ringbuf_submit(event_info, 0);

	char comm[128];
	bpf_get_current_comm(&comm, sizeof(comm));
	struct task_struct* task = bpf_get_current_task_btf();

#ifdef BPF_DEBUG
	bpf_printk("KRETPROBE CLOSE V4CON pid = %d/%d, ppid=%d, family = %d, addr2 = %d, addr3 = %d, comm = %s", 
		pid, BPF_CORE_READ(task, pid), BPF_CORE_READ(task, parent, pid), BPF_CORE_READ(*sk, __sk_common.skc_family), BPF_CORE_READ(*sk, __sk_common.skc_daddr), BPF_CORE_READ(*sk, __sk_common.skc_rcv_saddr), comm);
#endif

	return 0;
}

