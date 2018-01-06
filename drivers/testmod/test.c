#include <linux/init.h>
#include <linux/module.h>
MODULE_LICENSE("Dual BSD/GPL");

static int hello_init(void){
	asm(".byte 0xcd,0x14");
	printk(KERN_ERR "hello\n");
	return 0;
}

static void hello_exit(void){
	
}
module_init(hello_init);
module_exit(hello_exit);


