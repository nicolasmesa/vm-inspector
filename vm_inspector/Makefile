CC := arm-none-linux-gnueabi-gcc
LD := arm-none-linux-gnueabi-gcc
CFLAGS := -g -Wall -Werror -static
INCLUDE = -I. -I../flo-kernel/usr/include -I../flo-kernel/include -I../flo-kernel/arch/arm/include
LDFLAGS := -static $(INCLUDE)

OBJECTS := vm_inspector.o vm_inspector2.o

all: vm_inspector vm_inspector2


: $(OBJECTS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(OBJECTS)

%.o: %.c
	$(CC) $(CFLAGS) -c $^

clean:
	rm -f vm_inspector
	rm -f vm_inspector.o
	rm -f vm_inspector2
	rm -f vm_inspector2.o

.PHONY: clean
