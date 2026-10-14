/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */

#ifndef __ESTRACE_H
#define __ESTRACE_H

#define TASK_COMM_LEN 16
#define STACK_DEPTH 16

/* 标记事件来自系统调用入口还是出口。 */
enum event_type {
	EVENT_ENTER,
	EVENT_EXIT,
};

/* BPF 程序发送给用户态的事件结构；入口事件不使用 ret。 */
struct event {
	__u32 pid;
	__u32 uid;
	__u32 type;
	__s32 stack_size;
	__s64 syscall_nr;
	__s64 ret;
	char comm[TASK_COMM_LEN];
	__u64 user_stack[STACK_DEPTH];
};

#endif /* __ESTRACE_H */
