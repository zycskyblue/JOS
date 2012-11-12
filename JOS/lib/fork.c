// implement fork from user space

#include <inc/string.h>
#include <inc/lib.h>

// PTE_COW marks copy-on-write page table entries.
// It is one of the bits explicitly allocated to user processes (PTE_AVAIL).
#define PTE_COW		0x800

//
// Custom page fault handler - if faulting page is copy-on-write,
// map in our own private writable copy.
//
static void
pgfault(struct UTrapframe *utf)
{
	void *addr = (void *) utf->utf_fault_va;
	uint32_t err = utf->utf_err;
	int r;

	// Check that the faulting access was (1) a write, and (2) to a
	// copy-on-write page.  If not, panic.
	// Hint:
	//   Use the read-only page table mappings at vpt
	//   (see <inc/memlayout.h>).

	// LAB 4: Your code here.
	if ((err & FEC_WR) == 0) {
		panic("pgfault: error code does not contain FEC_WR!");
	}
	// redundant check, can be ommitted
	pde_t pde;
	pde = vpd[PDX(addr)];
	pte_t pte;
	pte = vpt[PGNUM(addr)];
	
	if ((pde & PTE_P) == 0) {
		panic("pgfault: pde not exists!");
	}
	// check PTE_COW enough
	if ((pte & (PTE_U | PTE_P | PTE_COW)) == 0) {
		panic("pgfault: permission error!");
	}

	// Allocate a new page, map it at a temporary location (PFTEMP),
	// copy the data from the old page to the new page, then move the new
	// page to the old page's address.
	// Hint:
	//   You should make three system calls.
	//   No need to explicitly delete the old page's mapping.

	// LAB 4: Your code here.

	r = sys_page_alloc(0, (void *)PFTEMP, PTE_U | PTE_P | PTE_W);
	if (r < 0) {
		panic("pgfault: %e", r);
	}

	memmove((void *)PFTEMP, (const void *)((PGNUM(addr)) << PTXSHIFT), PGSIZE);
	//sys_map_kernel_page(void* kpage, void* va);
	r = sys_page_map(0, (void *)PFTEMP, 0, (void *)((PGNUM(addr)) << PTXSHIFT), PTE_U | PTE_P | PTE_W);
	if (r < 0) {
		panic("pgfault: %e", r);
	}

	//panic("pgfault not implemented");
}

//
// Map our virtual page pn (address pn*PGSIZE) into the target envid
// at the same virtual address.  If the page is writable or copy-on-write,
// the new mapping must be created copy-on-write, and then our mapping must be
// marked copy-on-write as well.  (Exercise: Why do we need to mark ours
// copy-on-write again if it was already copy-on-write at the beginning of
// this function?)
//
// Returns: 0 on success, < 0 on error.
// It is also OK to panic on error.
//
static int
duppage(envid_t envid, unsigned pn)
{
	int r;
	
	uint32_t addr = pn * PGSIZE;
	if (addr >= UTOP) {
		panic("duppage: try to duplicate page above UTOP!");
	}
	
	// redundant check, can be ommitted
	pde_t pde;
	pde = vpd[PDX(addr)];
	
	// notice: we will pass the non-exist pte & pde sliently!
	if ((pde & PTE_P) != 0) {
		pte_t pte;
		pte = vpt[PGNUM(addr)];
		if ((pte & PTE_P) != 0) {
			if ((pte & (PTE_W | PTE_COW)) != 0) {
				//map copy on write - both
				r = sys_page_map(0, (void *)addr, envid, (void *)addr, PTE_U | PTE_P | PTE_COW);
				if (r < 0) {
					panic("duppage: %e", r);
				}
				r = sys_page_map(0, (void *)addr,     0, (void *)addr, PTE_U | PTE_P | PTE_COW);
				if (r < 0) {
					panic("duppage: %e", r);
				}
			}
			else {
				//map read
				r = sys_page_map(0, (void *)addr, envid, (void *)addr, PTE_U | PTE_P);
				if (r < 0) {
					panic("duppage: %e", r);
				}
			}
		}
	}
	
	// LAB 4: Your code here.
	//panic("duppage not implemented");
	return 0;
}

extern void _pgfault_upcall(void);

//
// User-level fork with copy-on-write.
// Set up our page fault handler appropriately.
// Create a child.
// Copy our address space and page fault handler setup to the child.
// Then mark the child as runnable and return.
//
// Returns: child's envid to the parent, 0 to the child, < 0 on error.
// It is also OK to panic on error.
//
// Hint:
//   Use vpd, vpt, and duppage.
//   Remember to fix "thisenv" in the child process.
//   Neither user exception stack should ever be marked copy-on-write,
//   so you must allocate a new page for the child's user exception stack.
//
envid_t
fork(void)
{
	// LAB 4: Your code here.
	envid_t envid;
	// step1
	set_pgfault_handler(pgfault);
	// step2
	envid = sys_exofork();
	if (envid < 0) {
		panic("fork: %e", envid);
	}

	// child
	if (envid == 0) {
		// fix thisenv
		thisenv = &envs[ENVX(sys_getenvid())];
		// child process should return 0
		return 0;
	}

	// parent

	// step3
	// notice : we shall skip exception stack
	unsigned i;
	// notice : unsigned type is error prone!
	for (i = 0; i < UTOP / PGSIZE - 1; i++) {
		duppage(envid, (unsigned)i);
	}

	int r;
	r = sys_page_alloc(envid, (void *)(UXSTACKTOP - PGSIZE), PTE_U | PTE_P | PTE_W);
	if (r < 0) {
		panic("fork: %e", r);
	}
	// step4
	// the same user page fault entrypoint in child as parent
	r = sys_env_set_pgfault_upcall(envid, (void *)_pgfault_upcall);
	if (r < 0) {
		panic("fork: %e", r);
	}

	// step5
	r = sys_env_set_status(envid, ENV_RUNNABLE);
	if (r < 0) {
		panic("fork: %e", r);
	}

	// parent should return child envid
	return envid;

	//panic("fork not implemented");
}

// Challenge!
int
sfork(void)
{
	panic("sfork not implemented");
	return -E_INVAL;
}
