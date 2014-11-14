#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/mman.h>


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

	if (argc > 1)
		pid = atoi(argv[1]);
	else
		pid = -1;


	address = mmap(0, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
	addr = (long) address;

	fake_pgd_addr = mmap(0, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);;
	fake_pgd = (long) fake_pgd_addr;

	ret = expose_page_table(pid, fake_pgd, addr);

	if (ret < 0)
		printf("Error: %s\n", strerror(errno));

	return 0;
}
