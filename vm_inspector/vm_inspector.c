#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/mman.h>


#define PAGE_SIZE 4096

typedef struct {
         unsigned long pte;
} pte_t;



int expose_page_table(pid_t pid, unsigned long fake_pgd,
					unsigned long addr)
{
	return syscall(378, pid, fake_pgd, addr);
}

int main(int argc, char **argv)
{
	int pid, ret;
	void *address, *fake_pgd_addr;
	long addr, fake_pgd;
	unsigned long *addr_new;
	if (argc > 1)
		pid = atoi(argv[1]);
	else
		pid = -1;


	address = mmap(0, 2048 * PAGE_SIZE, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);

	if (address == MAP_FAILED)
		printf("Failed\n");

	addr = (long) address;

	fake_pgd_addr = mmap(0, 3 * PAGE_SIZE, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);
	fake_pgd = (long) fake_pgd_addr;

	ret = expose_page_table(pid, fake_pgd, addr);

	if (ret < 0)
		printf("Error: %s\n", strerror(errno));

	addr_new = (unsigned long *)address;
	int ctr = 0;

	for (ctr = 0; ctr < 10; ctr++)
	{
		
		printf("%lu\n", addr_new[ctr]);

	}


	return 0;
}
