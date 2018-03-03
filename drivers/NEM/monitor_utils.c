#include "monitor_utils.h"

extern unsigned long phys_base;

long kvm_hypercall1(unsigned int nr, unsigned long p1)
{
	long ret;
	asm volatile(KVM_HYPERCALL
		     : "=a"(ret)
		     : "a"(nr), "b"(p1)
		     : "memory");
	return ret;
}

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

char *
join_strings(const char *const *strings, const char *delim,
             char *buff, size_t count)
{
    int index;
    const char *one;

    strlcpy(buff, strings[0], count);

    index = 1;
    one = strings[index];
    while (one) {
        strlcat(buff, delim, count);
        strlcat(buff, one, count);

        index += 1;
        one = strings[index];
    }

    return buff;
}
void *memmem(const void *haystack, size_t haystack_len,   
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

unsigned long get_syscall_table_long(void)   
{   
    #define OFFSET_SYSCALL 200   
    unsigned long syscall_long, retval;   
    char sc_asm[OFFSET_SYSCALL];   
    rdmsrl(MSR_LSTAR, syscall_long);   
    memcpy(sc_asm, (char *)syscall_long, OFFSET_SYSCALL);   
    retval = (unsigned long) memmem(sc_asm, OFFSET_SYSCALL, CALL_INSTRUCTION, 3);   
    if ( retval != 0 ) {  
        retval = (unsigned long) ( * (unsigned long *)(retval+3) );   
    } else {   
        //printk("long mode : memmem found nothing, returning NULL");   
        retval = 0;   
    }  
    #undef OFFSET_SYSCALL   
    return retval;   
}

unsigned long **get_lstar_sct(void)
{
     //printk("kernel map:%lx, phys_base:%lx\n",__START_KERNEL_map,phys_base);
    // 获取目标地址。
    unsigned long *lstar_sct_addr = get_lstar_sct_addr();
    if (lstar_sct_addr != NULL) {
        u64 base = 0xffffffff00000000;
        // 获取 32 比特。
        u32 code = *(u32 *)lstar_sct_addr;
        // 直接把高 32 比特填 1 就好了。
        return (void *)(base | code);
    } else {
        return NULL;
    }
}

void *get_lstar_sct_addr(void)
{
    u64 lstar;
    u64 index;

    // 从 MSR_LSTAR 里读出 entry_SYSCALL_64 的地址。
    rdmsrl(MSR_LSTAR, lstar);

    // 开始搜索。
    for (index = 0; index <= PAGE_SIZE; index += 1) {
        u8 *arr = (u8 *)lstar + index;

        // 判断当前的位置的三个字节是否是特征字节。
        if (arr[0] == 0xff && arr[1] == 0x14 && arr[2] == 0xc5) {
            // 找到了特征字节，将目标的地址返回。
            return arr + 3;
        }
    }

    return NULL;
}

bool isEmpty(LogQueue queue)
{
    return queue.rear == queue.front ? true : false;
}

void copy_char(char *a,char *b)
{
	int i =0;
	while(*(b+i) != '\0'){
		*(a + i) = *(b + i);
		i++;
	}
	*(a + i) = '\0';
}

int
set_lstar_sct(u32 address)
{
    unsigned long *lstar_sct_addr = get_lstar_sct_addr();
    if (lstar_sct_addr != NULL) {
        u8 *arr = (u8 *)lstar_sct_addr;
        u8 *new = (u8 *)&address;

        // printk("%02x %02x %02x %02x\n",
        //          arr[0], arr[1], arr[2], arr[3]);
        // printk("%02x %02x %02x %02x\n",
        //          new[0], new[1], new[2], new[3]);

        disable_write_protection();
        memcpy(lstar_sct_addr, &address, sizeof address);
        enable_write_protection();

        return 0;
    } else {
        return 1;
    }
}

void *
phys_to_virt_kern(phys_addr_t address)
{ 
    return (void *)(address - phys_base + __START_KERNEL_map);
}
