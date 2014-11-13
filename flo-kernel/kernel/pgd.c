#include<linux/unistd.h>
#include<linux/linkage.h>
#include<linux/kernel.h>
#include<linux/syscalls.h>

SYSCALL_DEFINE3(expose_page_table, pid_t, pid, unsigned long, fake_pgd, unsigned long, addr)
{
	printk(KERN_WARNING "expose_page_table called\n");

	return 0;

}

