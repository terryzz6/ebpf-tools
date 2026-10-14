#include <signal.h>
#include <stdio.h>
#include <unistd.h>

#include "hello_world.skel.h"

static volatile sig_atomic_t exiting;

static void sig_handler(int signal_number)
{
	(void)signal_number;
	exiting = 1;
}

int main(void)
{   
    // 定义一个结构体
	struct hello_world_bpf *obj;
	int err;
    
	obj = hello_world_bpf__open_and_load();
	if (!obj) {
		fprintf(stderr, "[zhou] failed to open and load BPF program\n");
		return 1;
	}

    //附加 eBPF程序
	err = hello_world_bpf__attach(obj);
	if (err) {
        //附加失败
		fprintf(stderr, "[zhou] failed to attach BPF program: %d\n", err);
		goto cleanup;
	}

	if (signal(SIGINT, sig_handler) == SIG_ERR ||
	    signal(SIGTERM, sig_handler) == SIG_ERR) {
		perror("[zhou] signal");
		err = 1;
		goto cleanup;
	}

	printf("[zhou] Tracing execve; press Ctrl-C to stop.\n");
    //判断是否退出
    while (!exiting)
		sleep(1);

cleanup:
	hello_world_bpf__destroy(obj);
	return err ? 1 : 0;
}
