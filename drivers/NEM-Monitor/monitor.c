#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/signal.h>
#include <linux/smp.h>
#include <linux/kthread.h>

MODULE_LICENSE("Dual BSD/GPL");

#define IA32_DEBUGCTL 0x1
#define IA32_DEBUGCTL_LBR			1UL << 0
#define MSR_IA32_DEBUGCTLMSR        0x000001d9
#define MSR_LBR_SELECT              0x000001c8
#define MSR_LBR_CORE_FROM            0x00000040
#define MSR_LBR_TOS					0x000001c9
#define MSR_LBR_CORE_TO              0x00000060
#define LBR_ENTRIES 16
#define LBR_SKIP 3
#define LBR_SELECT 0x185
#define LBR_FROM(from) (uint64_t)((((int64_t)from) << LBR_SKIP) >> LBR_SKIP)
static struct task_struct *ts;
struct lbr_t {
    uint64_t debug;   // contents of IA32_DEBUGCTL MSR
    uint64_t select;  // contents of LBR_SELECT
    uint64_t tos;     // index to most recent branch entry
    uint64_t from[LBR_ENTRIES];
    uint64_t   to[LBR_ENTRIES];
    struct task_struct *task; // pointer to the task_struct this state belongs to
};
struct lbr_t lbr;
void flush_lbr(bool enable) {
    int i;

    wrmsrl(MSR_LBR_TOS, 0);
    for (i = 0; i < LBR_ENTRIES; i++) {
        wrmsrl(MSR_LBR_NHM_FROM + i, 0);
        wrmsrl(MSR_LBR_NHM_TO   + i, 0);
    }
    if (enable) wrmsrl(MSR_IA32_DEBUGCTLMSR, IA32_DEBUGCTL);
    else        wrmsrl(MSR_IA32_DEBUGCTLMSR, 0);
}

void get_lbr(struct lbr_t *lbr) {
    int i;

    rdmsrl(MSR_IA32_DEBUGCTLMSR, lbr->debug);
    rdmsrl(MSR_LBR_SELECT,       lbr->select);
    rdmsrl(MSR_LBR_TOS,          lbr->tos);
    for (i = 0; i < LBR_ENTRIES; i++) {
        rdmsrl(MSR_LBR_NHM_FROM + i, lbr->from[i]);
        rdmsrl(MSR_LBR_NHM_TO   + i, lbr->to[i]);
        lbr->from[i] = LBR_FROM(lbr->from[i]);
    //    printk("lbr %d , form: %lx, to: %lx\n",lbr->from[i], lbr->to[i] );
    }
}
void dump_lbr(struct lbr_t *lbr) {
    int i;

    printk("MSR_IA32_DEBUGCTLMSR: 0x%llx\n", lbr->debug);
    printk("MSR_LBR_SELECT:       0x%llx\n", lbr->select);
    printk("MSR_LBR_TOS:          %lld\n", lbr->tos);
    for (i = 0; i < LBR_ENTRIES; i++) {
      printk("MSR_LBR_NHM_FROM[%2d]: 0x%llx\n", i, lbr->from[i]);
      printk("MSR_LBR_NHM_TO  [%2d]: 0x%llx\n", i, lbr->to[i]);
    }
}
void thread_core_1(void)
{
	long msr_from_counter1 = 1664, msr_to_counter1 = 1728, ax1f, dx1f, ax1t, dx1t;
	int i=0;
	asm volatile(
		"xor %%rdx, %%rdx;"
		"xor %%rax, %%rax;"
		"inc %%rax;"
		"movq $0x1d9, %%rcx;"
		"wrmsr;"
		:
		:
		);
	printk("set LBR\n");
	asm volatile (
		"xor %%rdx, %%rdx;"
		"xor %%rax, %%rax;"
		"inc %%rax;"
		"mov $0x1c8, %%rcx;"
		"wrmsr;"
		:
		:
		:
		);
	// for(msr_from_counter1 = 1664, msr_to_counter1 = 1728; msr_from_counter1 < 1680 ; 
	// 	msr_from_counter1++,msr_to_counter1++)
	// {
		printk("ssssssss i:%d\n",i++);
		asm volatile(
			"mov %4, %%rcx;"
			"rdmsr;"
			"mov %%rax, %0;"
			"mov %%rdx, %1;"
			"mov %5, %%rcx;"
			"rdmsr;"
			"mov %%rax, %2;"
			"mov %%rdx, %3;"
			: "=g" (ax1f), "=g"(dx1f), "=g"(ax1t), "=g"(dx1t)
			: "g" (msr_from_counter1), "g"(msr_to_counter1)
			: "%rax", "%rcx", "rdx"
			);
		printk("On cpu %d, brand from: %8x (MSR: %X), to %8x (MSR： %X)\n", smp_processor_id(), ax1f, msr_from_counter1, ax1t, msr_to_counter1);
	// }
	if(kthread_should_stop())
	{
		printk("stop thread\n");
		return 0;
	}
//	do_exit(0);
}

int init_module(void)
{
	// get_cpu();
 //    wrmsrl(MSR_LBR_SELECT, LBR_SELECT);	 
	// flush_lbr(true);
	// get_lbr(&lbr);
	// dump_lbr(&lbr);
	// put_cpu();
	ts = kthread_create(thread_core_1, NULL, "kTH");
	printk("create thread cpu: %d\n",smp_processor_id());

	kthread_bind(ts, 0);
	printk("bind success\n");
	if(!IS_ERR(ts))
		wake_up_process(ts);
	else
		printk("error to bind thread\n");
//	get_lbr(&lbr);
	return 0;
}

void cleanup_module(void)
{
	printk("NEM goodbye!");
}
