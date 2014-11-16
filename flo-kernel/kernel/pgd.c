#include <linux/unistd.h>
#include <linux/linkage.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/pid.h>
#include <linux/uaccess.h>

SYSCALL_DEFINE3(expose_page_table, pid_t, pid, unsigned long, fake_pgd,
unsigned long, addr)
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
	unsigned long va = 0, pfn, nil = 0;
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

	fake_pdg_addr = (unsigned long *) fake_pgd;

	curr_mm = current->mm;

	mm = p->mm;
	mmap = mm->mmap;

	vma = find_vma(curr_mm, addr);

	/* Shouldn't happen */
	if (vma == NULL)
		return -EINVAL;

	/* Don't know what to do in this case */
	if (vma->vm_start > addr || vma->vm_end < addr) {
		printk(KERN_DEBUG "Returned VMA that doesn't contain
address: Pid: %d\t\tStart address: %lu\t\tEnd address: %lu\t\tAddress:
%lu\n", p->pid, vma->vm_start, vma->vm_end, addr);
		return -EINVAL;
	}


	for (i = 0; i < 1536; i++) {
		pgd = pgd_offset(mm, va);

		if (copy_to_user(fake_pdg_addr, &nil, sizeof(unsigned long)))
			return -EFAULT;

		if (pgd_present(*pgd)) {
			pud = pud_offset(pgd, va);

			if (pud_none(*pud) || pud_bad(*pud)) {
				va += PAGE_SIZE * 512;
				fake_pdg_addr++;
				continue;
			}
			pmd = pmd_offset(pud, va);
			if (pmd_none(*pmd) || pmd_bad(*pmd)) {
				va += PAGE_SIZE * 512;
				fake_pdg_addr++;
				continue;
			}

			pte = pte_offset_map(pmd, va);

			if (pte == NULL) {
				printk("Was null\n");
				va += PAGE_SIZE * 512;
				fake_pdg_addr++;
				continue;
			}

			if (pte_none(*pte)) {
				va += PAGE_SIZE * 512;
				fake_pdg_addr++;
				continue;
			}

			pfn = __phys_to_pfn(pmd_val(*pmd) & PHYS_MASK);
			down_read(&curr_mm->mmap_sem);
			s = remap_pfn_range(vma, addr, pfn, PAGE_SIZE,
				vma->vm_page_prot);
			up_read(&curr_mm->mmap_sem);
			pte_unmap(pte);

			if (s) {
				printk(KERN_DEBUG "Error! %d\n", s);
				return -EINVAL;
			}

			if (copy_to_user(fake_pdg_addr, &addr,
				sizeof(unsigned long)))
					return -EINVAL;
			addr += PAGE_SIZE;
		}
		va += PAGE_SIZE * 512;
		fake_pdg_addr++;
	}
	return 0;
}
