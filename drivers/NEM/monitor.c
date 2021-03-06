#include <linux/timer.h>
#include <linux/string.h>
#include <asm-generic/asm-offsets.h>
#include "monitor.h"
#include "lbr.h"
MODULE_LICENSE("GPL");
#define MAX_BUF_LEN 1024 
unsigned long *sys_table = NULL;
static struct timer_list my_timer;
LogQueue *NEM_log;
phys_addr_t  real_phys;
int report_length;

unsigned long *fake_sct[__NR_syscall_max + 1] = { 0 };

asmlinkage long
fake_execve(const char __user *filename,
            const char __user *const __user *argv,
            const char __user *const __user *envp);
asmlinkage long
(*real_execve)(const char __user *filename,
               const char __user *const __user *argv,
               const char __user *const __user *envp);

asmlinkage long (*real_open)(const char *filename, int flags,umode_t mode);
asmlinkage long fake_open(const char __user *filename, int flags, umode_t mode);

asmlinkage char* my_function(void);
unsigned long old_sysenter;
extern asmlinkage void my_stub(void);
unsigned long handler_code=(unsigned long)&my_function;

static char *read_line(char *buf, int buf_len, struct file *fp)  
{  
        int ret;  
        int i = 0;  
        mm_segment_t fs;  
        loff_t pos;
        fs=get_fs();  
        set_fs(KERNEL_DS);  
    	pos =0;
    	vfs_read(fp, buf, sizeof(buf), &pos);
        set_fs(fs);  
  		printk("3333 buf is %s\n", buf);
        // if (ret <= 0)  
        //         return NULL;  
  
        // while(buf[i++] != '\n' && i < ret);  
  
        // if(i < ret) {  
        //         fp->f_pos += i-ret;  
        // }  
  
        // if(i < buf_len) {  
        //         buf[i] = 0;  
        // }  
        return buf;  
}  

void read_config(void)
{
	struct file *file = filp_open(CONFIG_PATH, O_RDWR | O_CREAT,0644); 
	char token[100]; 
	char buf[100]; 
	mm_segment_t fs;  
    loff_t pos;
    fs=get_fs();  
    set_fs(KERNEL_DS);  
    pos =0;
    vfs_read(file, buf, sizeof(buf), &pos);
    set_fs(fs);
    buf[18] = '\0';
     printk(KERN_ALERT "buf: %s\n", buf);
    int i=0,j=0;
	int buf_len = strlen(buf);
	printk(KERN_ALERT "buf length is %d\n",buf_len);
	 for (i=0; i<buf_len; i++)
	 {
	 	//printk("buf %d is %c", i, buf[i]);
	 	if(buf[i] != '=')
	 	{
	 		token[j] = buf[i];
	 		//printk(KERN_ALERT "token %d is %c",j, token[j]);
	 		j++;
	 		continue;
	 	}
	 	else
	 	{
	 		token[j] = '\0';
	 		if(!strcmp(token, "report_length"))
	 		{
	 			//printk(KERN_ALERT "equal as 'report_length'\n ");
	 			int k=0;
	 			char char_len[buf_len-j-2];
	 			j++;
	 			for(k=0;k<buf_len-j+1;k++){
	 				char_len[k] = buf[j++];
	 				printk("char len:%c", char_len[k]);
	 			}
	 			char_len[k] = '\0';
	 			char *stop;
	 			printk(KERN_ALERT "char_len is %s",char_len);
	 			report_length = simple_strtoul(char_len, &stop, 10);
	 			printk(KERN_ALERT "report length is %d", report_length);
	 			break;
	 		}
	 	}
	 }
	filp_close(file,NULL);
}

void stub_trtr(void){
	printk(KERN_ALERT "stub_trtr\n");
        __asm__(".globl my_stub        \n"
                ".align 4,0x90        \n"
                "my_stub:        \n"
                "        call *%0        \n"
                "        jmp *%1                \n"
                ::"m"(handler_code),"m"(old_sysenter));
}

asmlinkage char* my_function(){
	printk(KERN_ALERT "my_function\n");
        // struct thread_info *info=current_thread_info();
        // struct task_struct *task=info->task;
        int my_rax;
        __asm__("movl %%rax,%0;":"=r"(my_rax));
        printk(KERN_ALERT "process is %s", current->comm);
        //counts[my_rax]++;
        return;
}

int init_logQueue(void)
{
	NEM_log = (LogQueue *)kmalloc(sizeof(LogQueue), GFP_KERNEL);
	NEM_log->front = NEM_log->rear = (struct NEM_Node *)kmalloc(sizeof(struct NEM_Node), GFP_KERNEL);
	if(NULL == NEM_log->front){
		return -1;
	}
	NEM_log->front->next = NULL;
	NEM_log->number = 0;
	return 1;
}

int insertQueue(struct NEM_Node *node)
{
	NEM_log->rear->next = node;
	NEM_log->rear = node;
	
	NEM_log->number++;
	return 0;
}

int deleteQueue(void)
{
	struct NEM_Node *node = NULL;
	if(!isEmpty(*NEM_log)){
		node = NEM_log->front->next;
		//printk("delete node.args: %s, pid: %d \n", NEM_log->front->next->args, node->pid);
		NEM_log->front->next = node->next;
		if(NEM_log->rear == node){
			NEM_log->rear = NEM_log->front;
		}
		kfree(node->args);
		kfree(node->comm);
		kfree(node);
	}	
}

void destroyQueue(void)
{
	 while (NEM_log->front != NULL) {
         NEM_log->rear = NEM_log->front->next;
         kfree(NEM_log->front);
         NEM_log->front = NEM_log->rear;
     }
}

void monitor_code(char *args, int flag)
{
	struct NEM_Node *nem_data = (struct NEM_Node *)kmalloc(sizeof(struct NEM_Node), GFP_KERNEL);
	char *temp_args = kmalloc(PAGE_SIZE, GFP_KERNEL);
	char *temp_comm = kmalloc(PAGE_SIZE, GFP_KERNEL);
	//nem_data->sys_name = kmalloc(20, GFP_KERNEL);
	copy_char(temp_args, args);
	copy_char(temp_comm, current->comm);
	nem_data->args = temp_args;
	nem_data->comm = temp_comm;
	nem_data->pid = current->pid;
	nem_data->next = NULL;
	if(flag == 1){
		nem_data->sys_name = "execve";
	}else if(flag == 2){
		nem_data->sys_name = "open";
	}
	insertQueue(nem_data);	
	//printk(KERN_ALERT "NEM_MONITOR: syscall %s args:%s, process comm:%s, process pid:%d\n",nem_data->sys_name ,temp_args,temp_comm,current->pid);
	if(NEM_log->number >= report_length){
		reportMonitor();
	}
}

void  start_monitor(char *args, int flag)
{
	static int rax = 0, rcx = 0;
	struct lbr_t lbr;
	asm volatile("movq %%rax,%%rdx"			
			:"=a"(rax)	
			:
			:"%rdx");
	asm volatile("movq %%rcx,%%rdx"			
			:"=c"(rcx)
			:
			:"%rdx");
			
	asm volatile(VMX_VMFUNC
		:
		: "a"(0),"c"(1)
		: "cc");
	monitor_code(args, flag);
	

	//printk(KERN_ALERT "syscall exec args: %s, The process is \"%s\"(pid is %i)\n",nem_data->args, current->comm,current->pid);

	asm volatile(VMX_VMFUNC
		:
		: "a"(0),"c"(0)
		: "cc");		
	asm volatile("movq %%rax,%%rdx"			
			:
			:"a"(rax)
			:"%rdx");
	asm volatile("movq %%rcx,%%rdx" 		
			:
			:"c"(rcx)
			:"%rdx");

}

void reportMonitor(void)
{
	kvm_hypercall1(11, NEM_log);
//	printk("front: %lx, rear: %lx\n",NEM_log->front, NEM_log->rear);
	while(NEM_log->number > 0){
		deleteQueue();
		NEM_log->number--;
//		printk("111 number:%d\n", NEM_log->number);
	}
}

void unhook_syscall(void)
{
	disable_write_protection();
	sys_table[__NR_execve] = real_execve;
//	sys_table[__NR_open]=(unsigned long*)real_open;
	enable_write_protection();
}

asmlinkage long fake_open(const char __user *filename, int flags, umode_t mode)
{
	int a = 33;
	int rcx = 0;
  if ((flags & O_CREAT) && strcmp(filename, "/dev/null") != 0) {
    //printk(KERN_ALERT "open: %s\n", filename);   
    start_monitor(filename, 2);
  }

  return real_open(filename, flags, mode);
}

asmlinkage long
fake_execve(const char __user *filename,
            const char __user *const __user *argv,
            const char __user *const __user *envp)
{
	long ret;
    char *args;
    char *buff;;
    buff = kmalloc(PAGE_SIZE, GFP_KERNEL);
    if (buff != NULL) {
        args = join_strings(argv, " ", buff, PAGE_SIZE);
    } else {
        args = (char *)argv[0];
        buff = NULL;
    }
    start_monitor(args, 1);
 //   asm(".byte 0xcd,0x14");
    kfree(buff);
    ret = real_execve(filename, argv, envp);
    return ret;
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
	printk("The offset of comm: %lx \n", (size_t)&(((struct task_struct *)0)->comm));
	printk("The offset of list_head next: %lx \n", (size_t)&(((struct list_head *)0)->next));
	printk("sizeof thread_info: %d\n", sizeof(task_thread_info(task)));
	printk("The size of stack: %d \n", sizeof((struct thread_info *)(task)->stack));
	printk("The address of thread_info: %lx \n", (unsigned long)&(task->thread_info));
//	struct task_struct *a = task->stack->task;
//	printk("name of task:%s \n", a->comm);
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
	return NULL;
}
unsigned long long x86_get_msr(int msr)
{
 unsigned long msrl = 0, msrh = 0;
/* NOTE: rdmsr is always return EDX:EAX pair value */
 asm volatile ("rdmsr" :"=a"(msrl),"=d"(msrh) :"c"(msr));
 printk("msrl: %llx, msrh: %llx", msrl,msrh);
 return ((unsigned long long)msrh <<32) | msrl;
}

void print_tasks(void)
{
	int i=0;
	struct task_struct *swapper = &init_task;
	unsigned long next_process;
	struct task_struct *p;
	struct list_head *head = swapper->tasks.next;
	p = list_entry(head, struct task_struct, tasks);
	printk("task%d %s,address:%lx, tasks:%lx\n", i, p->comm, p, &p->tasks);
	struct list_head *tmp_next = p->tasks.next;
	printk(KERN_ALERT "head address:%lx, next: %lx,comm add:%lx, pid add:%lx\n", head, tmp_next,&p->comm, &p->pid);
	while(tmp_next != head)
	//while(i<5)
	{
	 //	printk("next address: %lx\n", tmp_next);
	 	p = list_entry(tmp_next, struct task_struct, tasks);
	 	printk("task%d %s,address:%lx, tasks:%lx, comm add:%lx, pid add:%lx\n", i, p->comm, p, &p->tasks, &p->comm, &p->pid);
	 	tmp_next = tmp_next->next;
	 	i++;
	}
}
void hook_all(void)
{
	unsigned int a;
	rdmsrl(MSR_IA32_SYSENTER_EIP,old_sysenter);
	 printk(KERN_ALERT "old MSR_IA32_SYSENTER_EIP:%lx\n",old_sysenter);
    wrmsrl(MSR_IA32_SYSENTER_EIP,my_stub);
    printk(KERN_ALERT "MSR_IA32_SYSENTER_EIP:%lx\n",my_stub);
}
int init_module(void)
{
//	struct NEM_log *nem;
	int ret;
	int j=0;
	unsigned long func_address;
//	nem->syscall_number = 2;
//	func_address = (unsigned long)NEM_Monitor;
//	 int pid = 17868;
//	 struct task_struct *task = get_task_by_pid(pid);
//	enable_lbr();
 	init_logQueue();
	// printk("LBR value: %llx\n", x86_get_msr(MSR_IA32_DEBUGCTLMSR));
	// printk("select:%llx\n", x86_get_msr(MSR_LBR_SELECT));
	// printk("select:%llx\n", x86_get_msr(MSR_LBR_TOS));
	
	// hook_syscall();
	struct task_struct *task = &init_task;
	//printk("init_task address: %lx, name:%s\n", task, task->comm);
	//print_offset_of_task(task);
	unsigned long **real_sct = get_lstar_sct();
	real_phys = virt_to_phys(real_sct);
	// printk("real sys_call_table: %p phys: %llx\n",
 //             real_sct, virt_to_phys(real_sct));
 //    printk("fake sys_call_table: %p phys: %llx\n",
 //             fake_sct, virt_to_phys(fake_sct));
	memcpy(fake_sct, real_sct, sizeof fake_sct);
	HOOK_SCT(fake_sct, execve);
	HOOK_SCT(fake_sct, open);
	set_lstar_sct((u32)(unsigned long)fake_sct);

//	printk(KERN_ALERT "monitor address %lx\n", monitor_code);

//	printk(" pid: %d, state:%ld, flags: %x,  stack: %x\n", task->pid, task->state, task->flags, task->stack);
	// for(j = 0;j < 16;j++){
 //       printk(KERN_ALERT "%c",task->comm[j]);
 //    }
//	kvm_hypercall1(2, (unsigned long)nem);
//	kvm_hypercall1(9, func_address);
//	print_tasks();
//	kvm_hypercall1(18, phys_base);
	kvm_hypercall1(10, &init_task);
	read_config();
	printk(KERN_ALERT "insmod NEM Monitor.\n");
	return 0;
}

void cleanup_module(void)
{
	set_lstar_sct((u32)(unsigned long)phys_to_virt_kern(real_phys));
	destroyQueue();

	asm volatile(VMX_VMFUNC
	:
	: "a"(0),"c"(0)
	: "cc");
	//printk(KERN_ALERT "NEM goodbye!");
}
