#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/mman.h>


#define PAGE_SIZE 4096
#define PGD_COUNT 1536
#define PGD_PAGE_COUNT 3

#define PGDIR_SHIFT             21
#define pgd_index(addr)         ((addr) >> PGDIR_SHIFT)

#define PHYS_MASK 0xFFFFF000
#define FLAGS_MASK 0x00000FFF
#define PRESENT_BIT 0x001
#define YOUNG_BIT 0x002
#define FILE_BIT 0x004
#define DIRTY_BIT 0x040
#define READ_BIT 0x080
#define XN_BIT 0x200

void print_pte(unsigned long *address, int pgd_index, int pte_index,
int verbose)
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
	unsigned long pgd_address;


	if (address == NULL)
		return;

	pte = *address;

	pgd_address = pgd_index * 512 * PAGE_SIZE;
	va = pgd_address + pte_index * PAGE_SIZE;

	phys_addr = pte & PHYS_MASK;

	if (phys_addr == 0 && verbose == 0)
		return;

	flags = pte & FLAGS_MASK;

	/*present = ((flags & PRESENT_BIT) == PRESENT_BIT);*/
	young_bit = ((flags & YOUNG_BIT) == YOUNG_BIT);
	file_bit = ((flags & FILE_BIT) == FILE_BIT);
	dirty_bit = ((flags & DIRTY_BIT) == DIRTY_BIT);
	read_only = ((flags & READ_BIT) == READ_BIT);
	xn = ((flags & XN_BIT) == XN_BIT);

	printf("0x%x\t0x%08lx\t0x%08lx\t%u\t%u\t%u\t%u\t%u\n",
	pgd_index, va, phys_addr, young_bit, file_bit, dirty_bit,
	read_only, xn);
}


void print_pte_table(unsigned long *address, int index, int verbose)
{
	int i;

	if (address == NULL)
		return;

	for (i = 0; i < 512; i++)
		print_pte(address++, index, i, verbose);
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
	unsigned long addr, fake_pgd, index;
	unsigned long **fake_pgd_new;
	int verbose = 0, ctr = 0;

	if (argc < 2 || argc > 3) {

		printf("Usage: ./vm_inspector <pid : use -1 for this proc>");
		printf("-v (for verbose)\n");
		exit(1);
	}

	pid = atoi(argv[1]);

	if (argc == 3) {
		if (strcmp(argv[2], "-v") == 0)
			verbose = 1;
		else {
			printf("Usage: ./vm_inspector <pid : use -1");
			printf(" for this proc>");
			printf("-v (for verbose)\n");
			exit(1);
		}
	}

	address = mmap(0, PGD_COUNT * PAGE_SIZE, PROT_READ,
		MAP_SHARED|MAP_ANONYMOUS, -1, 0);

	if (address == MAP_FAILED) {
		printf("Error: %s\n", strerror(errno));
		return 1;
	}

	addr = (unsigned long) address;

	fake_pgd_addr = mmap(0, PGD_PAGE_COUNT * PAGE_SIZE,
	PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);

	if (fake_pgd_addr == MAP_FAILED) {
		printf("Error: %s\n", strerror(errno));
		munmap(address, PGD_COUNT * PAGE_SIZE);
		return 1;
	}

	fake_pgd = (long) fake_pgd_addr;

	ret = expose_page_table(pid, fake_pgd, addr);

	if (ret < 0) {
		munmap(address, PGD_COUNT * PAGE_SIZE);
		munmap(fake_pgd_addr, PGD_PAGE_COUNT * PAGE_SIZE);

		printf("Error: %s\n", strerror(errno));
		exit(1);
	}

	fake_pgd_new = (unsigned long **) fake_pgd_addr;

	index = pgd_index(addr);

	printf("Index: %lu verbose: %d\n", index, verbose);

	for (ctr = 0; ctr < PGD_COUNT; ctr++) {
		if (fake_pgd_new[ctr] != NULL) {
			print_pte_table(fake_pgd_new[ctr], ctr, verbose);
			continue;
		}
	}

	munmap(address, PGD_COUNT * PAGE_SIZE);
	munmap(fake_pgd_addr, PGD_PAGE_COUNT * PAGE_SIZE);

	return 0;
}
