// SPDX-License-Identifier: GPL-2.0

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#include "estrace.h"

/*
 * ARM64 raw_syscalls/sys_enter 和 sys_exit 的 tracepoint 数据布局：
 *
 *   offset 0: trace_entry 公共字段
 *   offset 8: syscall 编号
 *   offset 16: 入口的参数数组，或出口的返回值
 *
 * 这里使用固定布局，不使用 CO-RE，因此设备不需要提供内核 BTF。
 */
struct raw_syscalls_sys_enter_ctx {
	__u64 common;
	__s64 syscall_nr;
};

struct raw_syscalls_sys_exit_ctx {
	__u64 common;
	__s64 syscall_nr;
	__s64 ret;
};

_Static_assert(__builtin_offsetof(struct raw_syscalls_sys_enter_ctx, syscall_nr) == 8,
	       "raw_syscalls/sys_enter 的调用编号偏移必须为 8");
_Static_assert(__builtin_offsetof(struct raw_syscalls_sys_exit_ctx, ret) == 16,
	       "raw_syscalls/sys_exit 的返回值偏移必须为 16");

/* 使用 perf event array，将事件发送到用户态。 */
struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__type(key, __u32);
	__type(value, __u32);
} events SEC(".maps");

/* 忽略本程序进程，避免打印和符号解析产生的系统调用反复触发追踪。 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} ignored_pid SEC(".maps");

static __always_inline bool is_ignored(__u32 pid)
{
	__u32 key = 0;
	__u32 *ignored = bpf_map_lookup_elem(&ignored_pid, &key);

	return ignored && pid == *ignored;
}

/* 入口事件记录系统调用编号和用户态堆栈；不读取参数或返回值。 */
SEC("tracepoint/raw_syscalls/sys_enter")
int tracepoint__raw__syscalls__sys_enter(
	struct raw_syscalls_sys_enter_ctx *ctx)
{
	struct event event = {};

	event.pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
	if (is_ignored(event.pid))
		return 0;

	event.uid = (__u32)bpf_get_current_uid_gid();
	event.type = EVENT_ENTER;
	event.syscall_nr = ctx->syscall_nr;
	bpf_get_current_comm(event.comm, sizeof(event.comm));
	event.stack_size = bpf_get_stack(ctx, event.user_stack,
					 sizeof(event.user_stack), BPF_F_USER_STACK);

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
			      &event, sizeof(event));
	return 0;
}

/* 出口事件记录系统调用编号和返回值。 */
SEC("tracepoint/raw_syscalls/sys_exit")
int tracepoint__raw__syscalls__sys_exit(
	struct raw_syscalls_sys_exit_ctx *ctx)
{
	struct event event = {};

	event.pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
	if (is_ignored(event.pid))
		return 0;

	event.uid = (__u32)bpf_get_current_uid_gid();
	event.type = EVENT_EXIT;
	event.syscall_nr = ctx->syscall_nr;
	event.ret = ctx->ret;
	bpf_get_current_comm(event.comm, sizeof(event.comm));

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
			      &event, sizeof(event));
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
