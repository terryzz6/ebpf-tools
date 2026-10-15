#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#include "estrace.h"

const volatile __u32 targ_pid = 0;
const volatile __u32 targ_tgid = 0;
const volatile __u32 targ_uid = INVALID_UID;
const volatile __s64 targ_sys_id = -1;
const volatile bool targ_failed = false;
const volatile bool targ_callers = false;

_Static_assert(__builtin_offsetof(struct trace_event_raw_sys_enter, args) == 16,
	       "sys_enter args offset");
_Static_assert(__builtin_offsetof(struct trace_event_raw_sys_exit, ret) == 16,
	       "sys_exit ret offset");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__type(key, __u32);
	__type(value, __u32);
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, __u32);
	__type(value, struct args_t);
} start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} ignored_pid SEC(".maps");

static __always_inline bool trace_allowed(__u32 tgid, __u32 tid)
{
	__u32 key = 0;
	__u32 *ignored = bpf_map_lookup_elem(&ignored_pid, &key);

	if (ignored && tgid == *ignored)
		return false;
	if (targ_tgid && targ_tgid != tgid)
		return false;
	if (targ_pid && targ_pid != tid)
		return false;
	if (targ_uid != INVALID_UID && targ_uid != (__u32)bpf_get_current_uid_gid())
		return false;
	return true;
}

SEC("tracepoint/raw_syscalls/sys_enter")
int tracepoint_raw_syscalls__sys_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	__u32 tid = id;
	struct args_t args = {};

	if (!trace_allowed(id >> 32, tid) ||
	    (targ_sys_id >= 0 && targ_sys_id != ctx->id))
		return 0;

	args.sys_id = ctx->id;
	args.args[0] = ctx->args[0];
	args.args[1] = ctx->args[1];
	args.args[2] = ctx->args[2];
	args.args[3] = ctx->args[3];
	args.args[4] = ctx->args[4];
	args.args[5] = ctx->args[5];
	bpf_map_update_elem(&start, &tid, &args, BPF_ANY);
	return 0;
}

SEC("tracepoint/raw_syscalls/sys_exit")
int tracepoint_raw_syscalls__sys_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	__u32 tid = id;
	struct args_t *args;
	struct event event = {};

	args = bpf_map_lookup_elem(&start, &tid);
	if (!args)
		return 0;
	if (args->sys_id != ctx->id || (targ_failed && ctx->ret >= 0))
		goto cleanup;

	event.pid = id >> 32;
	event.tid = tid;
	event.uid = (__u32)bpf_get_current_uid_gid();
	event.sys_id = args->sys_id;
	event.ret = ctx->ret;
	bpf_get_current_comm(event.comm, sizeof(event.comm));
	event.args[0] = args->args[0];
	event.args[1] = args->args[1];
	event.args[2] = args->args[2];
	event.args[3] = args->args[3];
	event.args[4] = args->args[4];
	event.args[5] = args->args[5];
	if (targ_callers)
		event.stack_size = bpf_get_stack(ctx, event.callers,
					      sizeof(event.callers), BPF_F_USER_STACK);
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));

cleanup:
	bpf_map_delete_elem(&start, &tid);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
