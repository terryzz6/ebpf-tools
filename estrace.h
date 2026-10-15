#ifndef __ESTRACE_H
#define __ESTRACE_H

#define TASK_COMM_LEN 16
#define STACK_DEPTH 16
#define INVALID_UID ((__u32)-1)
#define ESTRACE_NR_OPENAT 56
#define OPENAT_PATH_LEN 192

struct args_t {
	__s64 sys_id;
	__u64 args[6]; //存放系统调用参数 。最多 6 个参数 x0-x5
	__s32 path_len;
	char path[OPENAT_PATH_LEN];// openat 打开的路径
};

struct event {
	__u32 pid;
	__u32 tid;
	__u32 uid;
	__s32 stack_size;
	__s64 sys_id;
	__s64 ret;
	__u64 args[6];//堆栈信息
	__u64 callers[STACK_DEPTH];
	char comm[TASK_COMM_LEN];
	__s32 path_len;
	char path[OPENAT_PATH_LEN];// openat 调用的路径
};

#endif /* __ESTRACE_H */
