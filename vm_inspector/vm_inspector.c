#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/mman.h>


#define PAGE_SIZE 4096

#define PGDIR_SHIFT             21
#define pgd_index(addr)         ((addr) >> PGDIR_SHIFT)

#define PHYS_MASK 0xFFFFF000
#define FLAGS_MASK 0x00000FFF
#define YOUNG_BIT 0b000000000010
#define FILE_BIT 0b000000000100
#define DIRTY_BIT 0b000001000000
#define READ_BIT 0b000010000000
#define XN_BIT 0b001000000000

typedef struct {
	unsigned long pte;
} pte_t;


void print_pte(unsigned long *address, int index)
{
	unsigned long pte;
	unsigned long va;
	unsigned long phys_addr;
	unsigned long flags;
	unsigned int young_bit;
	unsigned int file_bit;
	unsigned int dirty_bit;
	unsigned int read_only;
	unsigned int xn;


	if (address == NULL)
		return;

	pte = *address;
	va = (unsigned long) address;
	phys_addr = pte & PHYS_MASK;

	if (phys_addr == 0)
		return;

	flags = pte & FLAGS_MASK;

	young_bit = ((flags & YOUNG_BIT) == YOUNG_BIT);
	file_bit = ((flags & FILE_BIT) == FILE_BIT);
	dirty_bit = ((flags & DIRTY_BIT) == DIRTY_BIT);
	read_only = ((flags & READ_BIT) == READ_BIT);
	xn = ((flags & XN_BIT) == XN_BIT);

	printf("0x%x\t0x%lx\t0x%lx\t%u\t%u\t%u\t%u\t%u\n",
index, va, phys_addr, young_bit, file_bit, dirty_bit, read_only, xn);
}


void print_pte_table(unsigned long *address, int index)
{
	int i;

	if (address == NULL)
		return;

	for (i = 0; i < 512; i++)
		print_pte(address++, index);
}

int expose_page_table(pid_t pid, unsigned long fake_pgd,
					unsigned long addr)
{
	return syscall(378, pid, fake_pgd, addr);
}

int main(int argc, char **argv)
{
	int pid, ret;
	void *address, *fake_pgd_addr;
	long addr, fake_pgd, index;
	unsigned long **fake_pgd_new;

	if (argc > 1)
		pid = atoi(argv[1]);
	else
		pid = -1;
	address = mmap(0, 1536 * PAGE_SIZE, PROT_READ,
		MAP_SHARED|MAP_ANONYMOUS, -1, 0);
	/*address = mmap(0, 2048 * PAGE_SIZE, PROT_READ|PROT_WRITE,
	MAP_SHARED|MAP_ANONYMOUS, -1, 0);*/

	if (address == MAP_FAILED)
		printf("Failed\n");

	addr = (long) address;

	fake_pgd_addr = mmap(0, 3 * PAGE_SIZE, PROT_READ|PROT_WRITE,
		MAP_SHARED|MAP_ANONYMOUS, -1, 0);
	fake_pgd = (long) fake_pgd_addr;

	ret = expose_page_table(pid, fake_pgd, addr);

	if (ret < 0)
		printf("Error: %s\n", strerror(errno));

	fake_pgd_new = (unsigned long **) fake_pgd_addr;

	int ctr = 0;

	index = pgd_index(addr);

	printf("Index: %lu\n", index);

	for (ctr = 0; ctr < 1536; ctr++) {
		if (fake_pgd_new[ctr] != NULL) {
			print_pte_table(fake_pgd_new[ctr], ctr);
			continue;
		}
	}
	return 0;
}
