#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/signal.h>
#include <asm/msr.h>
#include "monitor_utils.h"
#define VMX_VMFUNC ".byte 0x0f,0x01,0xd4"
#define CONFIG_PATH "/root/nem_config.conf"
# define HOOK_SCT(sct, name)                    \
    do {                                        \
        real_##name = (void *)sct[__NR_##name]; \
        sct[__NR_##name] = (void *)fake_##name; \
    } while (0)

# define UNHOOK_SCT(sct, name)                  \
    sct[__NR_##name] = (void *)real_##name
 
struct NEM_Node{
	char *sys_name;
	char *args;
	char *comm;	
	int pid;
	struct NEM_Node *next;
};

int insertQueue(struct NEM_Node *node);
int init_logQueue(void);
void reportMonitor(void);
void copy_char(char *a,char *b);