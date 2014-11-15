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
	int i, s = 0;
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;
	unsigned long va = 0, pfn;
	unsigned long *fake_pdg_addr;

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


	for (i = 0; i < 2048; i++) {
		pgd = pgd_offset(mm, va);

		if (pgd_present(*pgd)) {
			pud = pud_offset(pgd, va);

			if (pud_none(*pud) || pud_bad(*pud)) {
				//printk("Pud not present %d\n", i);
				va += PAGE_SIZE * 512;
				continue;
			}

			pmd = pmd_offset(pud, va);
		
			if (pmd_none(*pmd) || pmd_bad(*pmd)) {
				//printk("Pmd not present %d\n", i);
				va += PAGE_SIZE * 512;
				continue;
			}

			pte = pte_offset_map(pmd, va);

			if (pte == NULL) {
				printk("Was null\n");
				va += PAGE_SIZE * 512;
				continue;
			}

			if (pte_none(*pte)) {
				//printk("PTE none\n");
				va += PAGE_SIZE * 512;
				continue;
			}


			if (pte_present(*pte)) {
				pfn = __phys_to_pfn(pmd_val(*pmd) & PHYS_MASK);
				printk("Present %d:\t\taddr = %lu\t\ttaddr2 = %lu\n", i, (unsigned long int) *pmd, (unsigned long int) *pte);
				down_read(&curr_mm->mmap_sem);
				s = remap_pfn_range(vma, addr, pfn, PAGE_SIZE, vma->vm_page_prot);
				up_read(&curr_mm->mmap_sem);
				pte_unmap(pte);
				addr += PAGE_SIZE;
			} else {
				printk("Not present %d\n", i);
			}
		} else {
			printk("PGD not present %lu\n", va);
		}
		va += PAGE_SIZE * 512;
	}
	
	//printk("Pid: %d\t\tStart address: %lu\t\tEnd address: %lu\t\tAddress: %lu\n", p->pid, vma->vm_start, vma->vm_end, addr);

	return 0;
}

