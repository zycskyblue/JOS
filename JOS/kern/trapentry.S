/* See COPYRIGHT for copyright information. */

#include <inc/mmu.h>
#include <inc/memlayout.h>
#include <inc/trap.h>

#include <kern/picirq.h>


###################################################################
# exceptions/interrupts
###################################################################

/* TRAPHANDLER defines a globally-visible function for handling a trap.
 * It pushes a trap number onto the stack, then jumps to _alltraps.
 * Use TRAPHANDLER for traps where the CPU automatically pushes an error code.
 *
 * You shouldn't call a TRAPHANDLER function from C, but you may
 * need to _declare_ one in C (for instance, to get a function pointer
 * during IDT setup).  You can declare the function with
 *   void NAME();
 * where NAME is the argument passed to TRAPHANDLER.
 */
#define TRAPHANDLER(name, num)						\
	.globl name;		/* define global symbol for 'name' */	\
	.type name, @function;	/* symbol type is function */		\
	.align 2;		/* align function definition */		\
	name:			/* function starts here */		\
	pushl $(num);							\
	jmp _alltraps

/* Use TRAPHANDLER_NOEC for traps where the CPU doesn't push an error code.
 * It pushes a 0 in place of the error code, so the trap frame has the same
 * format in either case.
 */
#define TRAPHANDLER_NOEC(name, num)					\
	.globl name;							\
	.type name, @function;						\
	.align 2;							\
	name:								\
	pushl $0;							\
	pushl $(num);							\
	jmp _alltraps

.text

/*
 * Lab 3: Your code here for generating entry points for the different traps.
 */

TRAPHANDLER_NOEC( func_divide, T_DIVIDE)
TRAPHANDLER_NOEC( func_debug, T_DEBUG)
TRAPHANDLER_NOEC( func_nmi, T_NMI)
TRAPHANDLER_NOEC( func_brkpt, T_BRKPT)
TRAPHANDLER_NOEC( func_oflow, T_OFLOW)
TRAPHANDLER_NOEC( func_bound, T_BOUND)
TRAPHANDLER_NOEC( func_illop, T_ILLOP)
TRAPHANDLER_NOEC( func_device, T_DEVICE)

TRAPHANDLER( func_dblflt, T_DBLFLT)
TRAPHANDLER( func_tss, T_TSS)
TRAPHANDLER( func_segnp, T_SEGNP)
TRAPHANDLER( func_stack, T_STACK)
TRAPHANDLER( func_gpflt, T_GPFLT)
TRAPHANDLER( func_pgflt, T_PGFLT)

TRAPHANDLER_NOEC( func_fperr, T_FPERR)

TRAPHANDLER( func_align, T_ALIGN)

TRAPHANDLER_NOEC( func_mchk, T_MCHK)
TRAPHANDLER_NOEC( func_simderr, T_SIMDERR)

TRAPHANDLER_NOEC( func_syscall, T_SYSCALL)

/*
* IRQs
*/

TRAPHANDLER_NOEC( func_irq_0, IRQ_OFFSET + 0);
TRAPHANDLER_NOEC( func_irq_1, IRQ_OFFSET + 1);
TRAPHANDLER_NOEC( func_irq_2, IRQ_OFFSET + 2);
TRAPHANDLER_NOEC( func_irq_3, IRQ_OFFSET + 3);
TRAPHANDLER_NOEC( func_irq_4, IRQ_OFFSET + 4);
TRAPHANDLER_NOEC( func_irq_5, IRQ_OFFSET + 5);
TRAPHANDLER_NOEC( func_irq_6, IRQ_OFFSET + 6);
TRAPHANDLER_NOEC( func_irq_7, IRQ_OFFSET + 7);
TRAPHANDLER_NOEC( func_irq_8, IRQ_OFFSET + 8);
TRAPHANDLER_NOEC( func_irq_9, IRQ_OFFSET + 9);
TRAPHANDLER_NOEC( func_irq_10, IRQ_OFFSET + 10);
TRAPHANDLER_NOEC( func_irq_11, IRQ_OFFSET + 11);
TRAPHANDLER_NOEC( func_irq_12, IRQ_OFFSET + 12);
TRAPHANDLER_NOEC( func_irq_13, IRQ_OFFSET + 13);
TRAPHANDLER_NOEC( func_irq_14, IRQ_OFFSET + 14);
TRAPHANDLER_NOEC( func_irq_15, IRQ_OFFSET + 15);



.globl sysenter_handler;
.type sysenter_handler, @function;
.align 2;
sysenter_handler:
/*
 * Lab 3: Your code here for system call handling
 */
/*
 * Since at this time, the %esp is set to the KSTACKTOP, and there is no more things saved.
 * We have to construct the Trapframe like the interrupt routine all by ourselves.
 */

    pushw $0x0;
    pushw $GD_UD|3;

    pushl %ebp;

    pushfl;

    pushw $0x0;
    pushw $GD_UT|3;

    pushl %esi;

    pushl $0;

    pushl $0;

    pushw $0x0;
    pushw %ds;

    pushw $0x0;
    pushw %es;

    pushal;

    movw $GD_KD, %ax;
    movw %ax, %ds;
    movw %ax, %es;

    pushl %esp;
    
    call syscall_wrapper;
    
    popl %esp;


    popal;

    popl %es;

    popl %ds;

    movl %ebp, %ecx;
    movl %esi, %edx;

    sysexit;

/*
 * Lab 3: Your code here for _alltraps
 */

_alltraps:

/*
 * Step 1	0x0 is padding
 */
pushw	$0x0
pushw	%ds
pushw	$0x0
pushw	%es
pushal

/*
 * Step 2	first move to %ax, since only this form is supported by Assembler
 */
movw	$GD_KD, %ax
movw	%ax, %ds
movw	%ax, %es

/*
 * Step 3	since the Trapframe stored at that address
 */
pushl	%esp

/*
 * Step 4
 */
call trap


