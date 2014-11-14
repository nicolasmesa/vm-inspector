#include <linux/unistd.h>
#include <linux/linkage.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/sched.h>
#include <linux/mm.h>

SYSCALL_DEFINE3(expose_page_table, pid_t, pid, unsigned long, fake_pgd, unsigned long, addr)
{
	struct mm_struct *mm, *curr_mm;
	struct vm_area_struct *mmap, *vma;
	struct task_struct *p;


	if (pid == -1)
		p = current;
	else 
		p =   find_task_by_vpid(pid);

	if (p == NULL)
		return -EINVAL;

	if (fake_pgd == 0)
		return -EINVAL;

	if (addr == 0)
		return -EINVAL;

	if (p->mm == NULL)
		return -EINVAL;

	curr_mm = curr->mm;

	mm = p->mm;
	mmap = mm->mmap;

	vma = find_vma(curr_mm, addr);

	/* Shouldn't happen */
	if (vma == NULL)
		return -EINVAL;

	/* Don't know what to do in this case */
	if (vma->vm_start > addr || vma->vm_end < addr) {
		printk("Returned VMA that doesn't contain address: Pid: %d\t\tStart address: %lu\t\tEnd address: %lu\t\tAddress: %lu\n", p->pid, vma->vm_start, vma->vm_end, addr);
		return -EINVAL;
	}
	

	

	printk("Pid: %d\t\tStart address: %lu\t\tEnd address: %lu\t\tAddress: %lu\n", p->pid, vma->vm_start, vma->vm_end, addr);

	return 0;
}

