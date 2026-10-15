

struct event
{
    unsigned int pid;
    unsigned int sys_id;//系统调用号
    char data[123];
};
