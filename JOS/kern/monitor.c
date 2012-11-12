// Simple command-line kernel monitor useful for
// controlling the kernel and exploring the system interactively.

#include <inc/stdio.h>
#include <inc/string.h>
#include <inc/memlayout.h>
#include <inc/assert.h>
#include <inc/x86.h>

#include <kern/console.h>
#include <kern/monitor.h>
#include <kern/kdebug.h>
#include <kern/trap.h>

#define CMDBUF_SIZE	80	// enough for one VGA text line


struct Command {
	const char *name;
	const char *desc;
	// return -1 to force monitor to exit
	int (*func)(int argc, char** argv, struct Trapframe* tf);
};

static struct Command commands[] = {
	{ "help", "Display this list of commands", mon_help },
	{ "kerninfo", "Display information about the kernel", mon_kerninfo },
	{ "backtrace", "Display stack backtrace", mon_backtrace },
};
#define NCOMMANDS (sizeof(commands)/sizeof(commands[0]))

unsigned read_eip();

/***** Implementations of basic kernel monitor commands *****/

int
mon_help(int argc, char **argv, struct Trapframe *tf)
{
	int i;

	for (i = 0; i < NCOMMANDS; i++)
		cprintf("%s - %s\n", commands[i].name, commands[i].desc);
	return 0;
}

int
mon_kerninfo(int argc, char **argv, struct Trapframe *tf)
{
	extern char entry[], etext[], edata[], end[];

	cprintf("Special kernel symbols:\n");
	cprintf("  entry  %08x (virt)  %08x (phys)\n", entry, entry - KERNBASE);
	cprintf("  etext  %08x (virt)  %08x (phys)\n", etext, etext - KERNBASE);
	cprintf("  edata  %08x (virt)  %08x (phys)\n", edata, edata - KERNBASE);
	cprintf("  end    %08x (virt)  %08x (phys)\n", end, end - KERNBASE);
	cprintf("Kernel executable memory footprint: %dKB\n",
		(end-entry+1023)/1024);
	return 0;
}

// Lab1 only
// read the pointer to the retaddr on the stack
static uint32_t
read_pretaddr() {
    uint32_t pretaddr;
    __asm __volatile("leal 4(%%ebp), %0" : "=r" (pretaddr)); 
    return pretaddr;
}

void
do_overflow(void)
{
    cprintf("Overflow success\n");
}

void
start_overflow(void)
{
	// You should use a techique similar to buffer overflow
	// to invoke the do_overflow function and
	// the procedure must return normally.

    // And you must use the "cprintf" function with %n specifier
    // you augmented in the "Exercise 9" to do this job.

    // hint: You can use the read_pretaddr function to retrieve 
    //       the pointer to the function call return address;

    char str[256] = {};
    int nstr = 0;
    char *pret_addr;

	// Your code here.
	// read pret_addr, the compiler inlined this function	
	//uint32_t ret_addr = read_pretaddr();
	
	pret_addr = (char *)read_pretaddr();
	
	//cprintf("stack addr: %x\n",pret_addr);
	// Move the return address
		
	*(uint32_t *)(pret_addr + 4) = *(uint32_t *)(pret_addr + 0);
	/*	
	*(pret_addr + 4) = *(pret_addr + 0);
	*(pret_addr + 5) = *(pret_addr + 1);
	*(pret_addr + 6) = *(pret_addr + 2);
	*(pret_addr + 7) = *(pret_addr + 3);
	*/

	// You must first save the original address, and then you can change it
	// Only need to change the last two bytes, since the first two bytes are the same
	nstr = 7;
	memset(str, 0xd, nstr);
	cprintf("%s%n", str, pret_addr+1);

	nstr = 104;
	memset(str, 0xd, nstr);
	cprintf("%s%n", str, pret_addr);


}

void
overflow_me(void)
{
        start_overflow();
}

int
mon_backtrace(int argc, char **argv, struct Trapframe *tf)
{
	// Your code here.

	// Read current ebp, because this is inline, movl %%ebp,%0
	uint32_t ebp = read_ebp();
	// Read the eip on the read_eip() stack, because it is a function call, so that the result is the current eip
	uint32_t eip; //= read_eip();

	struct Eipdebuginfo info;
	
	cprintf("Stack backtrace:\n");
	while (ebp != 0) {
		eip = *(uint32_t *)(ebp+4);
		//if ((int)*(uint32_t *)(ebp+8) == 5) break;
		cprintf("  ebp %08x  eip %08x  args %08x %08x %08x %08x %08x\n", ebp,
			 eip, *(uint32_t *)(ebp+8), *(uint32_t *)(ebp+12),
			 *(uint32_t *)(ebp+16), *(uint32_t *)(ebp+20), *(uint32_t *)(ebp+24));

		debuginfo_eip(eip, &info);

		int line = info.eip_line;
		uintptr_t addr = info.eip_fn_addr;
		//cprintf("%s  int line = %d  uint fn_addr = %x\n",info.eip_file, line, addr);

		cprintf("         %s:%d: ", info.eip_file, line);
		
 		int namelen = info.eip_fn_namelen;
		uintptr_t  name = (uintptr_t)info.eip_fn_name;	
		int i = 0;	
		for (;i < namelen; i++) {
			cprintf("%c", *(info.eip_fn_name + i));		
		}
		
		cprintf("+%d\n", eip - addr);

		//eip = * (uint32_t *) (ebp+4);
		/*		
		if (eip == eipr) {
			cprintf("The same!\n");		
		}
		eip = eipr;		
		*/		
		ebp = * (uint32_t *) ebp;
	}

    //overflow_me();
    cprintf("Backtrace success\n");
	return 0;
}



/***** Kernel monitor command interpreter *****/

#define WHITESPACE "\t\r\n "
#define MAXARGS 16

static int
runcmd(char *buf, struct Trapframe *tf)
{
	int argc;
	char *argv[MAXARGS];
	int i;

	// Parse the command buffer into whitespace-separated arguments
	argc = 0;
	argv[argc] = 0;
	while (1) {
		// gobble whitespace
		while (*buf && strchr(WHITESPACE, *buf))
			*buf++ = 0;
		if (*buf == 0)
			break;

		// save and scan past next arg
		if (argc == MAXARGS-1) {
			cprintf("Too many arguments (max %d)\n", MAXARGS);
			return 0;
		}
		argv[argc++] = buf;
		while (*buf && !strchr(WHITESPACE, *buf))
			buf++;
	}
	argv[argc] = 0;

	// Lookup and invoke the command
	if (argc == 0)
		return 0;
	for (i = 0; i < NCOMMANDS; i++) {
		if (strcmp(argv[0], commands[i].name) == 0)
			return commands[i].func(argc, argv, tf);
	}
	cprintf("Unknown command '%s'\n", argv[0]);
	return 0;
}

void
monitor(struct Trapframe *tf)
{
	char *buf;

	cprintf("Welcome to the JOS kernel monitor!\n");
	cprintf("Type 'help' for a list of commands.\n");

	if (tf != NULL)
		print_trapframe(tf);

	while (1) {
		buf = readline("K> ");
		if (buf != NULL)
			if (runcmd(buf, tf) < 0)
				break;
	}
}

// return EIP of caller.
// does not work if inlined.
// putting at the end of the file seems to prevent inlining.
unsigned
read_eip()
{
	uint32_t callerpc;
	__asm __volatile("movl 4(%%ebp), %0" : "=r" (callerpc));
	return callerpc;
}
