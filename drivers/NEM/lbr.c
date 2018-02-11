#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/signal.h>
#include <linux/smp.h>
#include <linux/kthread.h>
#include "lbr.h"
MODULE_LICENSE("Dual BSD/GPL");


static struct task_struct *ts;

void flush_lbr(bool enable) {
    int i;
    u64 debugctl;
    u64 temp;
    wrmsrl(MSR_LBR_TOS, 0);
    // for (i = 0; i < LBR_ENTRIES; i++) {
    //     wrmsrl(MSR_LBR_NHM_FROM + i, 0);
    //     wrmsrl(MSR_LBR_NHM_TO + i, 0);
    // }
    if (enable) {
    	rdmsrl(MSR_IA32_DEBUGCTLMSR, debugctl);
    	 printk("lbr debugctl: %llx\n", debugctl);
    	debugctl |= IA32_DEBUGCTL_LBR;
    	wrmsrl(MSR_IA32_DEBUGCTLMSR, debugctl);
    }
    else        
    	wrmsrl(MSR_IA32_DEBUGCTLMSR, 0);
    rdmsrl(MSR_IA32_DEBUGCTLMSR, temp);
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
     //   printk("form: %lx, to: %lx, task: %s\n",lbr->from[i], lbr->to[i], current->comm );
    }
}
void dump_lbr(struct lbr_t *lbr) {
    int i;
    printk("MSR_IA32_DEBUGCTLMSR: 0x%llx\n", lbr->debug);
    printk("MSR_LBR_SELECT:       0x%llx\n", lbr->select);
    printk("MSR_LBR_TOS:          %lld\n", lbr->tos);
    for (i = 0; i < LBR_ENTRIES; i++) {
      printk("MSR_LBR_CORE_FROM[%2d]: 0x%llx\n", i, lbr->from[i]);
      printk("MSR_LBR_CORE_TO  [%2d]: 0x%llx\n", i, lbr->to[i]);
    }
}

void enable_lbr(void)
{
	get_cpu();
    wrmsrl(MSR_LBR_SELECT, LBR_SELECT);	 
	flush_lbr(true);
	put_cpu();
}
