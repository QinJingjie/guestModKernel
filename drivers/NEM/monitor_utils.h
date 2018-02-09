#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>

#define KVM_HYPERCALL ".byte 0x0f,0x01,0xc1"
#define CALL_INSTRUCTION "\xff\x14\xc5"

typedef struct LogQueueStruct{
	struct NEM_Node *front, *rear;
	int number;
}LogQueue;

long kvm_hypercall1(unsigned int nr, unsigned long p1);
void *get_lstar_sct_addr(void);
unsigned long get_syscall_table_long(void);
void enable_write_protection(void);
void disable_write_protection(void);
char *join_strings(const char *const *strings, const char *delim,
             char *buff, size_t count);
bool isEmpty(LogQueue queue);
int set_lstar_sct(u32 address);
void *phys_to_virt_kern(phys_addr_t address);
unsigned long **get_lstar_sct(void);