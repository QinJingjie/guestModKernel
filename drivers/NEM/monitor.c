#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/list.h>
#include <linux/signal.h>

MODULE_LICENSE("Dual BSD/GPL");

#define KVM_HYPERCALL ".byte 0x0f,0x01,0xc1"

struct NEM_log{
	int syscall_number;	
}; 

static inline long kvm_hypercall1(unsigned int nr, unsigned long p1)
{
	long ret;
	asm volatile(KVM_HYPERCALL
		     : "=a"(ret)
		     : "a"(nr), "b"(p1)
		     : "memory");
	return ret;
}

static void  monitor(void)
{
	int i=0;
	asm(".byte 0xcd,0x03");
	asm(".byte 0xcd,0x03");
	asm(".byte 0xcd,0x03");
	asm(".byte 0xcd,0x03");
	asm(".byte 0xcd,0x03");
	asm(".byte 0xcd,0x03");
	asm(".byte 0xcd,0x03");
	asm(".byte 0xcd,0x03");
//	printk(KERN_ALERT "this is NEM monitor %lx!\n", monitor);
}

int kill_process_by_id(struct task_struct *task, int pid){
	long sigkill_value_0 = 0x0000000000000100;
	long sigkill_value_1 = 0x0000000000000000;
	unsigned long tif_sigpending = 1UL << 2;
	printk("flags :%lx\n", task->thread_info.flags);
	printk("sig :%lx\n", task->pending.signal.sig[1]);
	printk("sig address :%lx\n", &(task->pending.signal.sig[0]));
	memcpy(task + 0x6a0 + 0x10, &sigkill_value_0, sizeof(unsigned long));
	memcpy(task + 0x6a0, &sigkill_value_1, sizeof(unsigned long));
//	memcpy(&(task->pending.signal.sig[0]), &sigkill_value_0, sizeof(unsigned long));
	memcpy(task, &tif_sigpending, sizeof(unsigned long));
//	printk("sig :%lx\n", task->pending.signal.sig[0]);
	return 0;
}

void print_offset_of_task(struct task_struct *task){
	struct sigpending pending = task->pending;
	struct thread_info thread_info = task->thread_info;
//	int preempt_count = thread_info.preempt_count;
	printk("The address of task_struct: %lx, size of task_struct:%lx\n", (unsigned long)task, sizeof(struct task_struct));
	printk("The offset of pid: %lx , %lx\n", (unsigned long)&(task->pid)-(unsigned long)task, (size_t)&(((struct task_struct *)0)->pid));
	printk("The offset of tasks: %lx, %lx \n", (unsigned long)&(task->tasks)-(unsigned long)task, (size_t)&(((struct task_struct *)0)->tasks));
	printk("The offset of pending: %lx, %lx \n", (unsigned long)&(task->pending)-(unsigned long)task, (size_t)&(((struct task_struct *)0)->pending));
	printk("The offset of signal: %lx, %lx \n", (unsigned long)&(task->pending.signal)-(unsigned long)&(task->pending), (size_t)&(((struct  sigpending*)0)->signal));
	printk("The offset of thread_info: %lx, %lx \n", (unsigned long)&(task->thread_info)-(unsigned long)task, (size_t)&(((struct task_struct *)0)->thread_info));
	printk("The offset of thread_info flags: %lx \n", (unsigned long)&(task->thread_info.flags)-(unsigned long)&(task->thread_info));
}
struct task_struct* get_task_by_pid(int pid){
	struct task_struct *swapper = &init_task;
	struct task_struct *p;
	struct list_head *pos;
	list_for_each(pos, &swapper->tasks){
		p = list_entry(pos, struct task_struct, tasks);
		if((int)p->pid == pid){
			return p;
		}
	}
}

void signal_test(void){
	sigset_t myset;
	int i = 0;
	sigemptyset(&myset);
	sigaddset(&myset, SIGINT);
	sigaddset(&myset, SIGQUIT);
	sigaddset(&myset, SIGKILL);
	sigaddset(&myset, SIGSEGV);
	for(i=0;i < 64; ++i){
		printk("%lx\n", myset.sig[i]);
	}
}
int init_module(void)
{
	struct NEM_log *nem;
	int ret;
	int j=0;
	nem = (struct NEM_log *)kmalloc(sizeof(struct NEM_log), GFP_KERNEL);
	unsigned long func_address;
	nem->syscall_number = 2;
	func_address = (unsigned long)monitor;
	int pid = 5143;
	struct task_struct *task = get_task_by_pid(pid);
	print_offset_of_task(task);
	ret = kill_process_by_id(task, pid);
//	signal_test();

//	struct task_struct *task = &init_task;
//	struct task_struct *task = 0xffffffff81e10500;
//	monitor();
//	printk(KERN_ALERT "monitor address %lx\n", task);
//	printk(" pid: %d, state:%ld, flags: %x,  stack: %x\n", task->pid, task->state, task->flags, task->stack);
	// for(j = 0;j < 16;j++){
 //       printk(KERN_ALERT "%c",task->comm[j]);
 //    }
//	kvm_hypercall1(2, (unsigned long)nem);
//	kvm_hypercall1(9, func_address);
//	kvm_hypercall1(2, &monitor);
	return 0;
}

void cleanup_module(void)
{
	printk("goodbye!");
}
