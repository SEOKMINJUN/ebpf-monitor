//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define NAME_SIZE 64
#define MAX_SIZE 128

char __license[] SEC("license") = "Dual MIT/GPL";

struct createEvent {
	u64 timestamp;
	u32 pid;
	u32 uid;
	u32 ppid;
	u8 name[NAME_SIZE];
	u8 comm[MAX_SIZE];
	u8 argv[10][128];
	u8 envp[10][128];
	u32 flags;
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
	__type(value, struct createEvent);
} createRingBuffer SEC(".maps");


struct terminateEvent {
	u64 timestamp;
	u32 pid;
	u32 uid;
	u32 ppid;
	u32 code;
	u8 comm[NAME_SIZE];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
	__type(value, struct terminateEvent);
} terminateRingBuffer SEC(".maps");

//ProcessCreate
SEC("kprobe/do_execveat_common")
int kprobe_do_execveat_common(struct pt_regs *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	uid_t uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
	struct task_struct* task = bpf_get_current_task_btf();
	if(!task) return 0;

	//Get arguments from function
	int fd 					= (int)PT_REGS_PARM1_CORE(ctx);
	struct filename* struct_filename = (struct filename *)PT_REGS_PARM2_CORE(ctx);const char* filename = BPF_CORE_READ(struct_filename, name);
	const char* const* argv = (const char* const*)PT_REGS_PARM3_CORE(ctx);
	const char* const* envp = (const char* const*)PT_REGS_PARM4_CORE(ctx);
	int flags 				= (int)PT_REGS_PARM5_CORE(ctx);
	
	//Create event and push it to ringbuffer
	struct createEvent *event_info;

	event_info = bpf_ringbuf_reserve(&createRingBuffer, sizeof(struct createEvent), 0);
	if (!event_info) {
		return 0;
	}

	event_info->timestamp = bpf_ktime_get_ns();
	event_info->pid = pid;
	event_info->uid = uid;
	event_info->ppid = task->parent->pid;
	bpf_probe_read_str(event_info->name, sizeof(event_info->name), filename);
	bpf_get_current_comm(&event_info->comm, sizeof(event_info->comm));

	for(int i=0;i<10;i++){
		void* pointer;
		bpf_probe_read(&pointer, sizeof(pointer), &argv[i]);
		if(pointer == NULL){
		// bpf_printk("KPROBE ENTRY ARGV BREAK arg[%d]\n", i);
			break;
		}
		bpf_probe_read_str(event_info->argv[i], sizeof(event_info->argv[i]), pointer);
		// bpf_printk("KPROBE ENTRY ARGV pid = %d, arg[%d] = %s\n", pid, i, event_info->argv[i], event_info->name);
	}

	for(int i=0;i<10;i++){
		void* pointer;
		bpf_probe_read(&pointer, sizeof(pointer), &envp[i]);
		if(pointer == NULL){
		// bpf_printk("KPROBE ENTRY ENVP BREAK arg[%d]\n", i);
			break;
		}
		bpf_probe_read_str(event_info->envp[i], sizeof(event_info->envp[i]), pointer);
		// bpf_printk("KPROBE ENTRY ENTRY pid = %d, env[%d] = %s\n", pid, i, event_info->argv[i], event_info->name);
	}

	event_info->flags = flags;

	// bpf_printk("KPROBE ENTRY EXECVE pid = %d, uid = %d, fname = %s\n", pid, uid, event_info->name);
	
	bpf_ringbuf_submit(event_info, 0);
    return 0;
}

SEC("tp/sched/sched_process_exit")
int tp_process_exit(struct trace_event_raw_sched_process_template* ctx) {
	u64 tid = bpf_get_current_pid_tgid();
	pid_t pid = tid >> 32;
	uid_t uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
	
	// Ignore thread exit
	if((u32)tid != pid)
		return 0;
	
	struct task_struct *task;
	task = (struct task_struct *)bpf_get_current_task();
	if(!task)
		return 0;

	struct terminateEvent *event_info;

	event_info = bpf_ringbuf_reserve(&terminateRingBuffer, sizeof(struct terminateEvent), 0);
	if (!event_info) {
		return 0;
	}

	event_info->timestamp = bpf_ktime_get_ns();
	event_info->pid = pid;
	event_info->uid = uid;
	event_info->ppid = BPF_CORE_READ(task, parent, pid);
	bpf_get_current_comm(&event_info->comm, sizeof(event_info->comm));
	event_info->code = BPF_CORE_READ(task, exit_code);

	bpf_ringbuf_submit(event_info, 0);
	return 0;
}