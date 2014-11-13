#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>
int main(int argc, char **argv)
{

	syscall(378, 0, 0, 0);
	return 0;
}
