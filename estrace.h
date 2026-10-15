#ifndef __ESTRACE_H
#define __ESTRACE_H

#define TASK_COMM_LEN 16
#define STACK_DEPTH 16
#define INVALID_UID ((__u32)-1)

struct args_t {
	__s64 sys_id;
	__u64 args[6];
};

struct event {
	__u32 pid;
	__u32 tid;
	__u32 uid;
	__s32 stack_size;
	__s64 sys_id;
	__s64 ret;
	__u64 args[6];
	__u64 callers[STACK_DEPTH];
	char comm[TASK_COMM_LEN];
};

#endif /* __ESTRACE_H */
