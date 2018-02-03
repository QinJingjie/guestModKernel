#include <linux/init.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
MODULE_LICENSE("Dual BSD/GPL");
void **sys_call_table;
unsigned long **sct;
unsigned long *sys_table = NULL; 
asmlinkage long (*real_open)(const char *filename, int flags,umode_t mode);
asmlinkage long (*real_unlink)(const char __user *pathname);
asmlinkage long (*real_unlinkat)(int dfd, const char __user * pathname, int flag);

asmlinkage long fake_open(const char __user *filename, int flags, umode_t mode);
asmlinkage long fake_unlink(const char __user *pathname);
asmlinkage long fake_unlinkat(int dfd, const char __user * pathname, int flag);

int (*orig_write)(unsigned int fd, char *buf, unsigned int count);
void disable_write_protection(void)
{         
  unsigned long cr0 = read_cr0();
  clear_bit(16, &cr0);
  write_cr0(cr0);
}       
void enable_write_protection(void)
{            
  unsigned long cr0 = read_cr0();
  set_bit(16, &cr0);
  write_cr0(cr0);
}   

unsigned long **get_sys_call_table(void)
{   
  unsigned long **entry = (unsigned long **)PAGE_OFFSET;
    
  for (;(unsigned long)entry < ULONG_MAX; entry += 1) {
    if (entry[__NR_close] == (unsigned long *)sys_close) {
        return entry;
      }
  }

  return NULL;
}

static void *memmem(const void *haystack, size_t haystack_len,   
            const void *needle, size_t needle_len)   
{  
    const char *begin;   
    const char *const last_possible = (const char *) haystack + haystack_len - needle_len;  
    if (needle_len == 0){   
        /* The first occurrence of the empty string is deemed to occur at  
          the beginning of the string. */   
        return (void *) haystack;  
    }  
    if (__builtin_expect(haystack_len < needle_len, 0)){   
        return NULL;  
    }  
    for (begin = (const char *) haystack; begin <= last_possible; ++begin)   
    {   
        if (begin[0] == ((const char *) needle)[0]   
            && !memcmp((const void *) &begin[1],   
                  (const void *) ((const char *) needle + 1),   
                  needle_len - 1)){  
            return (void *) begin;   
        }  
    }  
    return NULL;   
}  

asmlinkage long fake_open(const char __user *filename, int flags, umode_t mode)
{
	int a = 33;
	int rcx = 0;
//  if ((flags & O_CREAT) && strcmp(filename, "/dev/null") != 0) {
    printk(KERN_ALERT "open: %s\n", filename);
//  }
  asm(".byte 0xcd,0x14");

  return real_open(filename, flags, mode);
}

int hacked_write(unsigned int fd,char *buf,unsigned int count)
{
	char *hide = "hello";
	if(strstr(buf,hide)!=NULL){
		printk(KERN_ALERT "find name in %s\n",buf);
	return count;
	}
	else{
		return orig_write(fd,buf,count);
	}
}

asmlinkage long fake_unlink(const char __user *pathname)
{
  printk(KERN_ALERT "unlink: %s\n", pathname);

  return real_unlink(pathname);
}

asmlinkage long fake_unlinkat(int dfd, const char __user * pathname, int flag)
{
  printk(KERN_ALERT "unlinkat: %s\n", pathname);

  return real_unlinkat(dfd, pathname, flag);
}

static unsigned long get_syscall_table_long(void)   
{   
    #define OFFSET_SYSCALL 200   
    unsigned long syscall_long, retval;   
    char sc_asm[OFFSET_SYSCALL];   
    rdmsrl(MSR_LSTAR, syscall_long);   
    memcpy(sc_asm, (char *)syscall_long, OFFSET_SYSCALL);   
    retval = (unsigned long) memmem(sc_asm, OFFSET_SYSCALL, "\xff\x14\xc5", 3);   
    if ( retval != 0 ) {  
        retval = (unsigned long) ( * (unsigned long *)(retval+3) );   
    } else {   
        printk("long mode : memmem found nothing, returning NULL:(");   
        retval = 0;   
    }  
    #undef OFFSET_SYSCALL   
    return retval;   
}  

int init_module(void)
{
//      asm(".byte 0xcd,0x14");
		disable_write_protection();
//		sct = (unsigned long**)(0xffff9abb9aa001c0);       
//        sct=get_sys_call_table();
//        printk(KERN_ALERT "sys call table:%lx\n",sct);
		sys_table = (unsigned long *) get_syscall_table_long();  
		sys_table = (unsigned long)sys_table | 0xffffffff00000000;   
		if (sys_table == 0){   
			printk("sys_table == 0/n");  
			return -1;  
		}  
		printk(KERN_ALERT "sys call table:%lx\n",sys_table);
        real_open = (void *)sys_table[__NR_open];
        sys_table[__NR_open] = (unsigned long*)fake_open;
		
		real_unlink = (void *)sys_table[__NR_unlink];
		sys_table[__NR_unlink] = (unsigned long*)fake_unlink;
		real_unlinkat = (void *)sys_table[__NR_unlinkat];
		sys_table[__NR_unlinkat] = (unsigned long*)fake_unlinkat;
//       orig_write = (void *)sct[__NR_write];
//        sct[__NR_write] = hacked_write;
        enable_write_protection();
		
        return 0;
}
void cleanup_module(void){
        disable_write_protection();
        sys_table[__NR_open]=(unsigned long*)real_open;
		sys_table[__NR_unlink] = (unsigned long*)real_unlink;
		sys_table[__NR_unlinkat] = (unsigned long*)real_unlinkat;
//        sct[__NR_write]=orig_write;
        enable_write_protection();
}

