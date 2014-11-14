#include <linux/unistd.h>
#include <linux/linkage.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/pid.h>

SYSCALL_DEFINE3(expose_page_table, pid_t, pid, unsigned long, fake_pgd, unsigned long, addr)
{
	struct mm_struct *mm, *curr_mm;
	struct vm_area_struct *mmap, *vma;
	struct task_struct *p;
	struct pid *pid_struct;
	int i, s;
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;
	spinlock_t *ptl;

	if (pid == -1)
		p = current;
	else {
		pid_struct = find_get_pid(pid);
		p = get_pid_task(pid_struct, PIDTYPE_PID);
	}

	if (p == NULL)
		return -EINVAL;

	if (fake_pgd == 0)
		return -EINVAL;

	if (addr == 0)
		return -EINVAL;

	if (p->mm == NULL)
		return -EINVAL;

	curr_mm = current->mm;

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


	pgd = pgd_offset(mm, 0);


	for (i = 0; i < 2048; i++) {
		if (pgd_present(pgd[i])) {
			pud = pud_offset(pgd + i, 0);

			if (pgd_none(*pgd) || pgd_bad(*pgd)) {
				//printk("Pud not present %d\n", i);
				continue;
			}

			pmd = pmd_offset(pud, 0);
		
			if (pmd_none(*pmd) || pmd_bad(*pmd)) {
				//printk("Pmd not present %d\n", i);
				continue;
			}

			pte = pte_offset_map(pmd, 0);

			if (pte == NULL) {
				//printk("Was null\n");
				continue;
			}

			if (pte_none(*pte)) {
				continue;
			}

			if (pte_present(*pte)) {
				printk("Present %d\n", i);
				down_read(&curr_mm->mmap_sem);

				if ((vma->vm_flags & (VM_SHARED | VM_MAYWRITE)) == VM_MAYWRITE) {
					printk("is_cow_mapping");
				}

				s = 0;
				s = remap_pfn_range(vma, addr, *pte, PAGE_SIZE, vma->vm_page_prot);
				printk("Return = %d\n", s);
				up_read(&curr_mm->mmap_sem);
				printk("After up\n");
				//pte_unmap(pte);
				printk("After unmap\n");
				return 0;
			} else {
				//printk("Not present %d\n", i);
			}
		}
	}
	
	//printk("Pid: %d\t\tStart address: %lu\t\tEnd address: %lu\t\tAddress: %lu\n", p->pid, vma->vm_start, vma->vm_end, addr);

	return 0;
}

