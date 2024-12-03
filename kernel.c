 #include "kernel.h"	// DO NOT EDIT!!!
#include "lib.h"	// DO NOT EDIT!!!

// kernel.c
//
//    This is the kernel.

// INITIAL PHYSICAL MEMORY LAYOUT
//
//  +-------------- Base Memory --------------+
//  v                                         v
// +-----+--------------------+----------------+--------------------+---------/
// |     | Kernel      Kernel |       :    I/O | App 1        App 1 | App 2
// |     | Code + Data  Stack |  ...  : Memory | Code + Data  Stack | Code ...
// +-----+--------------------+----------------+--------------------+---------/
// 0  0x40000              0x80000 0xA0000 0x100000             0x140000
//                                             ^
//                                             | \___ PROC_SIZE ___/
//                                      PROC_START_ADDR

#define PROC_SIZE 0x40000       // initial state only

static proc processes[NPROC];   // array of process descriptors
                                // Note that processes[0] is never used.
proc* current;                  // pointer to currently executing proc

#define HZ 100                  // timer interrupt frequency (interrupts/sec)
static unsigned ticks;          // # timer interrupts so far

void schedule(void);
void run(proc* p) __attribute__((noreturn));
void sys_exit();

static uint8_t disp_global = 1;         // global flag to display memviewer


// PAGEINFO
//
//    The pageinfo[] array keeps track of information about each physical page.
//    There is one entry per physical page.
//    pageinfo[pn] holds the information for physical page number pn.
//    You can get a physical page number from a physical address pa using
//    PAGENUMBER(pa). (This also works for page table entries.)
//    To change a physical page number pn into a physical address, use
//    PAGEADDRESS(pn).
//
//    pageinfo[pn].refcount is the number of times physical page pn is
//      currently referenced. 0 means it's free.
//    pageinfo[pn].owner is a constant indicating who owns the page.
//      PO_KERNEL means the kernel, PO_RESERVED means reserved memory (such
//      as the console), and a number >=0 means that process ID.
//
//    pageinfo_init() sets up the initial pageinfo[] state.

typedef struct physical_pageinfo {
    int8_t owner;
    int8_t refcount;
} physical_pageinfo;

static physical_pageinfo pageinfo[PAGENUMBER(MEMSIZE_PHYSICAL)];

typedef enum pageowner {
    PO_FREE = 0,                // this page is free
    PO_RESERVED = -1,           // this page is reserved memory
    PO_KERNEL = -2              // this page is used by the kernel
} pageowner_t;

static void pageinfo_init(void);


// Memory functions

void check_virtual_memory(void);
void memshow_physical(void);
void memshow_virtual(x86_64_pagetable* pagetable, const char* name);
void memshow_virtual_animate(void);


static void process_setup(pid_t pid, int program_number);
// x86_64_pagetable* assign_free_page(int8_t owner);
// uintptr_t alloc_free_page(int8_t owner);

int8_t current_owner = PO_KERNEL;  // This global variable stores the current owner

// wrapper for assign_free_page to make it compatible with program_load call
x86_64_pagetable* page_allocator(void) {
    return assign_free_page(current_owner);
}

// kernel(command)
//    Initialize the hardware and processes and start running. The command
//    string is an optional string passed from the boot loader.
void kernel(const char* command) {
    hardware_init();
    pageinfo_init();
    console_clear();
    timer_init(HZ);

    // memory mappings in kernel page table need to be initialized without any user permissions
    // include the console address as user accesible 

     // Set up the initial kernel page table mappings
    for (uintptr_t va = 0; va < PROC_START_ADDR; va += PAGESIZE) {
        vamapping vam = virtual_memory_lookup(kernel_pagetable, va);
        if (vam.pn != -1 && (vam.perm & PTE_P)) {
            // Map kernel pages with kernel-only permissions (no user access)
            virtual_memory_map(kernel_pagetable, va, vam.pa, PAGESIZE, PTE_P | PTE_W);
        }
    }

    // Map console memory as user-accessible
    virtual_memory_map(kernel_pagetable, CONSOLE_ADDR, CONSOLE_ADDR, PAGESIZE, PTE_P | PTE_W | PTE_U);

    // Set up process descriptors
    memset(processes, 0, sizeof(processes));
    for (pid_t i = 0; i < NPROC; i++) {
        processes[i].p_pid = i;
        processes[i].p_state = P_FREE;
    }

    if (command && strcmp(command, "fork") == 0) {
        process_setup(1, 4);
    } else if (command && strcmp(command, "forkexit") == 0) {
        process_setup(1, 5);
    } else if (command && strcmp(command, "test") == 0) {
        process_setup(1, 6);
    } else if (command && strcmp(command, "test2") == 0) {
        for (pid_t i = 1; i <= 2; ++i) {
            process_setup(i, 6);
        }
    } else {
        for (pid_t i = 1; i <= 4; ++i) {
            process_setup(i, i - 1);
        }
    }

    // Switch to the first process using run()
    run(&processes[1]);
}

void process_setup(pid_t pid, int program_number) {
    process_init(&processes[pid], 0);

    // allocate physical pages for page tables
    uintptr_t pt_pages[5];
    for (int i = 0; i < 5; i++) {
        pt_pages[i] = alloc_free_page(pid);
        if (!pt_pages[i]) {
            panic("Out of memory: Cannot allocate page table pages");
        }
        memset((void*) pt_pages[i], 0, PAGESIZE); // clear page table page to prevent data leakage
    }

    // set up page table pointers
    x86_64_pagetable* pt_l4 = (x86_64_pagetable*) pt_pages[0];
    x86_64_pagetable* pt_l3 = (x86_64_pagetable*) pt_pages[1];
    x86_64_pagetable* pt_l2 = (x86_64_pagetable*) pt_pages[2];
    x86_64_pagetable* pt_l1_0 = (x86_64_pagetable*) pt_pages[3];
    x86_64_pagetable* pt_l1_1 = (x86_64_pagetable*) pt_pages[4];

    // set up the page table hierarchy
    pt_l4->entry[0] = PTE_ADDR(pt_pages[1]) | PTE_P | PTE_W | PTE_U;
    pt_l3->entry[0] = PTE_ADDR(pt_pages[2]) | PTE_P | PTE_W | PTE_U;
    pt_l2->entry[0] = PTE_ADDR(pt_pages[3]) | PTE_P | PTE_W | PTE_U;
    pt_l2->entry[1] = PTE_ADDR(pt_pages[4]) | PTE_P | PTE_W | PTE_U;

    // assign the L4 page table to the process
    processes[pid].p_pagetable = pt_l4;

    // map kernel memory into the new page table
    for (uintptr_t va = 0; va < PROC_START_ADDR; va += PAGESIZE) {
        vamapping vam = virtual_memory_lookup(kernel_pagetable, va);
        if (vam.pn != -1 && (vam.perm & PTE_P)) {
            virtual_memory_map(pt_l4, va, vam.pa, PAGESIZE, vam.perm);
        }
    }

    // map console memory with PTE_U
    virtual_memory_map(pt_l4, CONSOLE_ADDR, CONSOLE_ADDR, PAGESIZE, PTE_P | PTE_W | PTE_U);

    // load the program into the process's memory
    int r = program_load(&processes[pid], program_number, page_allocator);
    assert(r >= 0);

    // allocate and map the process's stack
    processes[pid].p_registers.reg_rsp = MEMSIZE_VIRTUAL;  // set stack pointer to start of virtual memory
    uintptr_t stack_page = processes[pid].p_registers.reg_rsp - PAGESIZE;  // allocate the stack's first page
    uintptr_t stack_pa = alloc_free_page(pid);
    if (stack_pa == 0) {
        panic("Out of memory: Cannot allocate stack page");
    }
    r = virtual_memory_map(pt_l4, stack_page, stack_pa, PAGESIZE, PTE_P | PTE_W | PTE_U);
    assert(r >= 0);

    processes[pid].p_state = P_RUNNABLE;
}


// assign_physical_page(addr, owner)
//    Allocates the page with physical address addr to the given owner.
//    Fails if physical page addr was already allocated. Returns 0 on
//    success and -1 on failure. Used by the program loader.

int assign_physical_page(uintptr_t addr, int8_t owner) {
    if ((addr & 0xFFF) != 0
        || addr >= MEMSIZE_PHYSICAL
        || pageinfo[PAGENUMBER(addr)].refcount != 0) {
        return -1;
    } else {
        pageinfo[PAGENUMBER(addr)].refcount = 1;
        pageinfo[PAGENUMBER(addr)].owner = owner;
        return 0;
    }
}

void syscall_mapping(proc* p){

    uintptr_t mapping_ptr = p->p_registers.reg_rdi;
    uintptr_t ptr = p->p_registers.reg_rsi;

    //convert to physical address so kernel can write to it
    vamapping map = virtual_memory_lookup(p->p_pagetable, mapping_ptr);

    // check for write access
    if((map.perm & (PTE_W|PTE_U)) != (PTE_W|PTE_U))
        return;
    uintptr_t endaddr = mapping_ptr + sizeof(vamapping) - 1;
    // check for write access for end address
    vamapping end_map = virtual_memory_lookup(p->p_pagetable, endaddr);
    if((end_map.perm & (PTE_W|PTE_P)) != (PTE_W|PTE_P))
        return;
    // find the actual mapping now
    vamapping ptr_lookup = virtual_memory_lookup(p->p_pagetable, ptr);
    memcpy((void *)map.pa, &ptr_lookup, sizeof(vamapping));
}

void syscall_mem_tog(proc* process){

    pid_t p = process->p_registers.reg_rdi;
    if(p == 0) {
        disp_global = !disp_global;
    }
    else {
        if(p < 0 || p > NPROC || p != process->p_pid)
            return;
        process->display_status = !(process->display_status);
    }
}

// exception(reg)
//    Exception handler (for interrupts, traps, and faults).
//
//    The register values from exception time are stored in reg.
//    The processor responds to an exception by saving application state on
//    the kernel's stack, then jumping to kernel assembly code (in
//    k-exception.S). That code saves more registers on the kernel's stack,
//    then calls exception().
//
//    Note that hardware interrupts are disabled whenever the kernel is running.

void exception(x86_64_registers* reg) {
    // Copy the saved registers into the current process descriptor
    // and always use the kernel's page table.
    current->p_registers = *reg;
    set_pagetable(kernel_pagetable);

    // It can be useful to log events using log_printf.
    // Events logged this way are stored in the host's log.txt file.

    // Show the current cursor location and memory state
    // (unless this is a kernel fault).
    console_show_cursor(cursorpos);
    if ((reg->reg_intno != INT_PAGEFAULT && reg->reg_intno != INT_GPF) // no error due to pagefault or general fault
            || (reg->reg_err & PFERR_USER)) // pagefault error in user mode 
    {
        check_virtual_memory();
        if(disp_global){
            memshow_physical();
            memshow_virtual_animate();
        }
    }

    // If Control-C was typed, exit the virtual machine.
    check_keyboard();


    // Actually handle the exception.
    switch (reg->reg_intno) {

    case INT_SYS_PANIC:
	    // rdi stores pointer for msg string
	    {
		char msg[160];
		uintptr_t addr = current->p_registers.reg_rdi;
		if((void *)addr == NULL)
		    panic(NULL);
		vamapping map = virtual_memory_lookup(current->p_pagetable, addr);
		memcpy(msg, (void *)map.pa, 160);
		panic(msg);

	    }
	    panic(NULL);
	    break;                  // will not be reached

    case INT_SYS_GETPID:
        current->p_registers.reg_rax = current->p_pid;
        break;

    case INT_SYS_YIELD:
        schedule();
        break;                  /* will not be reached */


    case INT_SYS_PAGE_ALLOC: {
        uintptr_t va = current->p_registers.reg_rdi; // the virtual address requested
        // ensure the requested address is valid
        if (va < PROC_START_ADDR || va >= MEMSIZE_VIRTUAL || (va % PAGESIZE != 0)) {
            current->p_registers.reg_rax = -1;
            break;
        }

        // find a free physical page
        uintptr_t pa = alloc_free_page(current->p_pid);
        if (pa == 0) {
            current->p_registers.reg_rax = -1;
            break;
        }

        // map the physical page at the requested virtual address
        int result = virtual_memory_map(current->p_pagetable, va, pa, PAGESIZE, PTE_P | PTE_W | PTE_U);
        if (result < 0) {
            current->p_registers.reg_rax = -1;
        } else {
            current->p_registers.reg_rax = 0;
        }
        break;
    }
case INT_SYS_FORK: {
    // find a free process slot in the processes array
    pid_t child_pid = -1;
    for (pid_t i = 1; i < NPROC; ++i) {
        if (processes[i].p_state == P_FREE) {
            child_pid = i;
            break;
        }
    }

    if (child_pid == -1) {
        current->p_registers.reg_rax = -1; // no free process slot available
        break;
    }

    int dead = 0;

    // allocate physical pages for page tables 
    uintptr_t pt_pages[5];
    for (int i = 0; i < 5; i++) {
        pt_pages[i] = alloc_free_page(child_pid);
        if (!pt_pages[i]) {
            if (i>1){
                pageinfo[pt_pages[0]].owner = PO_FREE;
                pageinfo[pt_pages[0]].refcount = 0;
            }  
            if (i>2){
                pageinfo[pt_pages[1]].owner = PO_FREE;
                pageinfo[pt_pages[1]].refcount = 0;
            } 
            if (i>3){
                pageinfo[pt_pages[2]].owner = PO_FREE;
                pageinfo[pt_pages[2]].refcount = 0;
            }            
            if (i>4){
                pageinfo[pt_pages[3]].owner = PO_FREE;
                pageinfo[pt_pages[3]].refcount = 0;
            }
            current->p_registers.reg_rax = -1;
            dead = 1;
            break;
        }
        memset((void*) pt_pages[i], 0, PAGESIZE); // clear page table page to prevent data leakage
    }
    if (dead == 1) {
        break;
    }

    // set up page table pointers
    x86_64_pagetable* pt_l4 = (x86_64_pagetable*) pt_pages[0];
    x86_64_pagetable* pt_l3 = (x86_64_pagetable*) pt_pages[1];
    x86_64_pagetable* pt_l2 = (x86_64_pagetable*) pt_pages[2];
    x86_64_pagetable* pt_l1_0 = (x86_64_pagetable*) pt_pages[3];
    x86_64_pagetable* pt_l1_1 = (x86_64_pagetable*) pt_pages[4];

    // set up the page table hierarchy
    pt_l4->entry[0] = PTE_ADDR(pt_pages[1]) | PTE_P | PTE_W | PTE_U;
    pt_l3->entry[0] = PTE_ADDR(pt_pages[2]) | PTE_P | PTE_W | PTE_U;
    pt_l2->entry[0] = PTE_ADDR(pt_pages[3]) | PTE_P | PTE_W | PTE_U; // First 1GB
    pt_l2->entry[1] = PTE_ADDR(pt_pages[4]) | PTE_P | PTE_W | PTE_U; // Second 1GB

    // initialize child process descriptor
    proc* child = &processes[child_pid];
    //copy registers before process init
    memcpy(&(child->p_registers), &(current->p_registers), sizeof(x86_64_registers));
    // child->p_registers.reg_rcx = current->p_registers.reg_rcx;
    // child->p_registers.reg_rax = current->p_registers.reg_rax;
    // child->p_registers.reg_rdx = current->p_registers.reg_rdx;
    // child->p_registers.reg_rbx = current->p_registers.reg_rbx;
    // child->p_registers.reg_rbp = current->p_registers.reg_rbp;
    // child->p_registers.reg_rsi = current->p_registers.reg_rsi;
    // child->p_registers.reg_rdi = current->p_registers.reg_rdi;
    // child->p_registers.reg_r8 = current->p_registers.reg_r8;
    // child->p_registers.reg_r9 = current->p_registers.reg_r9;
    // child->p_registers.reg_r10 = current->p_registers.reg_r10;
    // child->p_registers.reg_r11 = current->p_registers.reg_r11;
    // child->p_registers.reg_r12 = current->p_registers.reg_r12;
    // child->p_registers.reg_r13 = current->p_registers.reg_r13;
    // child->p_registers.reg_r14 = current->p_registers.reg_r14;
    // child->p_registers.reg_r15 = current->p_registers.reg_r15;
    // child->p_registers.reg_fs = current->p_registers.reg_fs;
    // child->p_registers.reg_gs = current->p_registers.reg_gs;
    // child->p_registers.reg_intno = current->p_registers.reg_intno;
    // child->p_registers.reg_err = current->p_registers.reg_err;
    // child->p_registers.reg_rip = current->p_registers.reg_rip;
    // child->p_registers.reg_cs = current->p_registers.reg_cs;
    // child->p_registers.reg_padding2[0] = current->p_registers.reg_padding2[0];
    // child->p_registers.reg_padding2[1] = current->p_registers.reg_padding2[1];
    // child->p_registers.reg_padding2[2] = current->p_registers.reg_padding2[2];
    // child->p_registers.reg_rflags = current->p_registers.reg_rflags;
    // child->p_registers.reg_rsp = current->p_registers.reg_rsp;
    // child->p_registers.reg_ss = current->p_registers.reg_ss;
    // child->p_registers.reg_padding3[0] = current->p_registers.reg_padding3[0];
    // child->p_registers.reg_padding3[1] = current->p_registers.reg_padding3[1];
    // child->p_registers.reg_padding3[2] = current->p_registers.reg_padding3[2];

    // map kernel memory into the new page table
    for (uintptr_t va = 0; va < PROC_START_ADDR; va += PAGESIZE) {
        vamapping vam = virtual_memory_lookup(kernel_pagetable, va);
        if (vam.pn != -1 && (vam.perm & PTE_P)) {
            virtual_memory_map(pt_l4, va, vam.pa, PAGESIZE, vam.perm);
        }
    }

    // map console memory with PTE_U
    virtual_memory_map(pt_l4, CONSOLE_ADDR, CONSOLE_ADDR, PAGESIZE, PTE_P | PTE_W | PTE_U);

    // copy parent address space
    int failure = 0;
    uintptr_t allocated_pages[128]; // array to keep track of allocated pages
    int allocated_pages_count = 0;

    for (uintptr_t va = PROC_START_ADDR; va < MEMSIZE_VIRTUAL; va += PAGESIZE) {
        vamapping vam = virtual_memory_lookup(current->p_pagetable, va);
        if ((vam.perm & PTE_P) && vam.pn != -1) {
            if (vam.pa == CONSOLE_ADDR) {
                // share console memory
                if (virtual_memory_map(pt_l4, va, vam.pa, PAGESIZE, vam.perm) < 0) {
                    failure = 1;
                    break;
                }
            } else if ((vam.perm & PTE_W) == 0) {
                // share read only pages
                pageinfo[vam.pn].refcount++;
                if (virtual_memory_map(pt_l4, va, vam.pa, PAGESIZE, vam.perm) < 0) {
                    console_printf(CPOS(24, 0), 0x0C00, "fork: Failed to map shared read-only memory for child PID %d at va %p\n", child_pid, va);
                    failure = 1;
                    break;
                }
            } else {
                // allocate a new physical page and copy data from parent
                uintptr_t child_pa = (uintptr_t) alloc_free_page(child_pid);
                if (!child_pa) {
                    failure = 1;
                    break;
                }

                // track the allocated page in case cleanup is needed
                allocated_pages[allocated_pages_count++] = child_pa;

                //after succ copy pagetables, copy registers from parent to child ->call process init

                // copy the contents from parent to child
                memcpy((void*) child_pa, (void*) vam.pa, PAGESIZE);

                if (virtual_memory_map(pt_l4, va, child_pa, PAGESIZE, vam.perm) < 0) {
                    failure = 1;
                    break;
                }
            }
        }
    }
    
    child->p_pagetable = pt_l4;
    child->p_pid = child_pid;
    process_init(child, 0);
    

    if (failure == 1) {
        // cleanup on failure
        // goto fork_cleanup;
        sys_exit(child_pid);
        current->p_registers.reg_rax = -1;
        break;
    }

    // set up the child process's registers
    child->p_registers = current->p_registers;
    child->p_registers.reg_rax = 0;  // child returns 0 from fork
    child->p_state = P_RUNNABLE;

    // set the parent's return value
    current->p_registers.reg_rax = child_pid;
    break;

fork_cleanup:

    // free the page table pages
    for (int i = 0; i < 5; i++) {
        if (pt_pages[i]) {
            int pt_pn = PAGENUMBER(pt_pages[i]);
            pageinfo[pt_pn].refcount = 0;
            pageinfo[pt_pn].owner = PO_FREE;
        }
    }

    current->p_registers.reg_rax = -1;
    sys_exit(current->p_pid);
    break;
}

    case INT_SYS_MAPPING:
    {
	    syscall_mapping(current);
            break;
    }

    case INT_SYS_MEM_TOG:
	{
	    syscall_mem_tog(current);
	    break;
	}
    case INT_SYS_EXIT:
    {
        sys_exit(current->p_pid);
        break;
    }

    case INT_TIMER:
        ++ticks;
        schedule();
        break;                  /* will not be reached */

    case INT_PAGEFAULT: {
        // Analyze faulting address and access type.
        uintptr_t addr = rcr2();
        const char* operation = reg->reg_err & PFERR_WRITE
                ? "write" : "read";
        const char* problem = reg->reg_err & PFERR_PRESENT
                ? "protection problem" : "missing page";

        if (!(reg->reg_err & PFERR_USER)) {
            panic("Kernel page fault for %p (%s %s, rip=%p)!\n",
                  addr, operation, problem, reg->reg_rip);
        }
        console_printf(CPOS(24, 0), 0x0C00,
                       "Process %d page fault for %p (%s %s, rip=%p)!\n",
                       current->p_pid, addr, operation, problem, reg->reg_rip);
        current->p_state = P_BROKEN;
        sys_exit(current->p_pid);
        break;
    }

    default:
        default_exception(current);
        break;                  /* will not be reached */

    }


    // Return to the current process (or run something else).
    if (current->p_state == P_RUNNABLE) {
        run(current);
    } else {
        schedule();
    }
}

// schedule
//    Pick the next process to run and then run it.
//    If there are no runnable processes, spins forever.

void schedule(void) {
    pid_t pid = current->p_pid;
    while (1) {
        pid = (pid + 1) % NPROC;
        if (processes[pid].p_state == P_RUNNABLE) {
            run(&processes[pid]);
        }
        // If Control-C was typed, exit the virtual machine.
        check_keyboard();
    }
}


// run(p)
//    Run process p. This means reloading all the registers from
//    p->p_registers using the popal, popl, and iret instructions.
//
//    As a side effect, sets current = p.

void run(proc* p) {
    assert(p->p_state == P_RUNNABLE);
    current = p;

    // Load the process's current pagetable.
    set_pagetable(p->p_pagetable);

    // This function is defined in k-exception.S. It restores the process's
    // registers then jumps back to user mode.
    exception_return(&p->p_registers);

 spinloop: goto spinloop;       // should never get here
}


// pageinfo_init
//    Initialize the pageinfo[] array.

void pageinfo_init(void) {
    extern char end[];

    for (uintptr_t addr = 0; addr < MEMSIZE_PHYSICAL; addr += PAGESIZE) {
        int owner;
        if (physical_memory_isreserved(addr)) {
            owner = PO_RESERVED;
        } else if ((addr >= KERNEL_START_ADDR && addr < (uintptr_t) end)
                   || addr == KERNEL_STACK_TOP - PAGESIZE) {
            owner = PO_KERNEL;
        } else {
            owner = PO_FREE;
        }
        pageinfo[PAGENUMBER(addr)].owner = owner;
        pageinfo[PAGENUMBER(addr)].refcount = (owner != PO_FREE);
    }
}


// check_page_table_mappings
//    Check operating system invariants about kernel mappings for page
//    table pt. Panic if any of the invariants are false.

void check_page_table_mappings(x86_64_pagetable* pt) {
    extern char start_data[], end[];
    assert(PTE_ADDR(pt) == (uintptr_t) pt);

    // kernel memory is identity mapped; data is writable
    for (uintptr_t va = KERNEL_START_ADDR; va < (uintptr_t) end;
         va += PAGESIZE) {
        vamapping vam = virtual_memory_lookup(pt, va);
        if (vam.pa != va) {
            console_printf(CPOS(22, 0), 0xC000, "%p vs %p\n", va, vam.pa);
        }
        assert(vam.pa == va);
        if (va >= (uintptr_t) start_data) {
            assert(vam.perm & PTE_W);
        }
    }

    // kernel stack is identity mapped and writable
    uintptr_t kstack = KERNEL_STACK_TOP - PAGESIZE;
    vamapping vam = virtual_memory_lookup(pt, kstack);
    assert(vam.pa == kstack);
    assert(vam.perm & PTE_W);
}


// check_page_table_ownership
//    Check operating system invariants about ownership and reference
//    counts for page table pt. Panic if any of the invariants are false.

static void check_page_table_ownership_level(x86_64_pagetable* pt, int level,
                                             int owner, int refcount);

void check_page_table_ownership(x86_64_pagetable* pt, pid_t pid) {
    // calculate expected reference count for page tables
    int owner = pid;
    int expected_refcount = 1;
    if (pt == kernel_pagetable) {
        owner = PO_KERNEL;
        for (int xpid = 0; xpid < NPROC; ++xpid) {
            if (processes[xpid].p_state != P_FREE
                && processes[xpid].p_pagetable == kernel_pagetable) {
                ++expected_refcount;
            }
        }
    }
    check_page_table_ownership_level(pt, 0, owner, expected_refcount);
}

static void check_page_table_ownership_level(x86_64_pagetable* pt, int level,
                                             int owner, int refcount) {
    assert(PAGENUMBER(pt) < NPAGES);
    assert(pageinfo[PAGENUMBER(pt)].owner == owner);
    assert(pageinfo[PAGENUMBER(pt)].refcount == refcount);
    if (level < 3) {
        for (int index = 0; index < NPAGETABLEENTRIES; ++index) {
            if (pt->entry[index]) {
                x86_64_pagetable* nextpt =
                    (x86_64_pagetable*) PTE_ADDR(pt->entry[index]);
                check_page_table_ownership_level(nextpt, level + 1, owner, 1);
            }
        }
    }
}


// check_virtual_memory
//    Check operating system invariants about virtual memory. Panic if any
//    of the invariants are false.

void check_virtual_memory(void) {
    // Process 0 must never be used.
    assert(processes[0].p_state == P_FREE);

    // The kernel page table should be owned by the kernel;
    // its reference count should equal 1, plus the number of processes
    // that don't have their own page tables.
    // Active processes have their own page tables. A process page table
    // should be owned by that process and have reference count 1.
    // All level-2-4 page tables must have reference count 1.

    check_page_table_mappings(kernel_pagetable);
    check_page_table_ownership(kernel_pagetable, -1);

    for (int pid = 0; pid < NPROC; ++pid) {
        if (processes[pid].p_state != P_FREE
            && processes[pid].p_pagetable != kernel_pagetable) {
            check_page_table_mappings(processes[pid].p_pagetable);
            check_page_table_ownership(processes[pid].p_pagetable, pid);
        }
    }

    // Check that all referenced pages refer to active processes
    for (int pn = 0; pn < PAGENUMBER(MEMSIZE_PHYSICAL); ++pn) {
        if (pageinfo[pn].refcount > 0 && pageinfo[pn].owner >= 0) {
            assert(processes[pageinfo[pn].owner].p_state != P_FREE);
        }
    }
}

// memshow_physical
//    Draw a picture of physical memory on the CGA console.

static const uint16_t memstate_colors[] = {
    'K' | 0x0D00, 'R' | 0x0700, '.' | 0x0700, '1' | 0x0C00,
    '2' | 0x0A00, '3' | 0x0900, '4' | 0x0E00, '5' | 0x0F00,
    '6' | 0x0C00, '7' | 0x0A00, '8' | 0x0900, '9' | 0x0E00,
    'A' | 0x0F00, 'B' | 0x0C00, 'C' | 0x0A00, 'D' | 0x0900,
    'E' | 0x0E00, 'F' | 0x0F00, 'S'
};
#define SHARED_COLOR memstate_colors[18]
#define SHARED

void memshow_physical(void) {
    console_printf(CPOS(0, 32), 0x0F00, "PHYSICAL MEMORY");
    for (int pn = 0; pn < PAGENUMBER(MEMSIZE_PHYSICAL); ++pn) {
        if (pn % 64 == 0) {
            console_printf(CPOS(1 + pn / 64, 3), 0x0F00, "0x%06X ", pn << 12);
        }

        int owner = pageinfo[pn].owner;
        if (pageinfo[pn].refcount == 0) {
            owner = PO_FREE;
        }
        uint16_t color = memstate_colors[owner - PO_KERNEL];
        // darker color for shared pages
        if (pageinfo[pn].refcount > 1 && pn != PAGENUMBER(CONSOLE_ADDR)){
#ifdef SHARED
            color = SHARED_COLOR | 0x0F00;
#else
	    color &= 0x77FF;
#endif
        }

        console[CPOS(1 + pn / 64, 12 + pn % 64)] = color;
    }
}


// memshow_virtual(pagetable, name)
//    Draw a picture of the virtual memory map pagetable (named name) on
//    the CGA console.

void memshow_virtual(x86_64_pagetable* pagetable, const char* name) {
    assert((uintptr_t) pagetable == PTE_ADDR(pagetable));

    console_printf(CPOS(10, 26), 0x0F00, "VIRTUAL ADDRESS SPACE FOR %s", name);
    for (uintptr_t va = 0; va < MEMSIZE_VIRTUAL; va += PAGESIZE) {
        vamapping vam = virtual_memory_lookup(pagetable, va);
        uint16_t color;
        if (vam.pn < 0) {
            color = ' ';
        } else {
            assert(vam.pa < MEMSIZE_PHYSICAL);
            int owner = pageinfo[vam.pn].owner;
            if (pageinfo[vam.pn].refcount == 0) {
                owner = PO_FREE;
            }
            color = memstate_colors[owner - PO_KERNEL];
            // reverse video for user-accessible pages
            if (vam.perm & PTE_U) {
                color = ((color & 0x0F00) << 4) | ((color & 0xF000) >> 4)
                    | (color & 0x00FF);
            }
            // darker color for shared pages
            if (pageinfo[vam.pn].refcount > 1 && va != CONSOLE_ADDR) {
#ifdef SHARED
                color = (SHARED_COLOR | (color & 0xF000));
                if(! (vam.perm & PTE_U))
                    color = color | 0x0F00;

#else
		color &= 0x77FF;
#endif
            }
        }
        uint32_t pn = PAGENUMBER(va);
        if (pn % 64 == 0) {
            console_printf(CPOS(11 + pn / 64, 3), 0x0F00, "0x%06X ", va);
        }
        console[CPOS(11 + pn / 64, 12 + pn % 64)] = color;
    }
}


// memshow_virtual_animate
//    Draw a picture of process virtual memory maps on the CGA console.
//    Starts with process 1, then switches to a new process every 0.25 sec.

void memshow_virtual_animate(void) {
    static unsigned last_ticks = 0;
    static int showing = 1;

    // switch to a new process every 0.25 sec
    if (last_ticks == 0 || ticks - last_ticks >= HZ / 2) {
        last_ticks = ticks;
        ++showing;
    }

    // the current process may have died -- don't display it if so
    while (showing <= 2*NPROC
           && (processes[showing % NPROC].p_state == P_FREE || processes[showing % NPROC].display_status == 0)) {
        ++showing;
    }
    showing = showing % NPROC;

    if (processes[showing].p_state != P_FREE) {
        char s[4];
        snprintf(s, 4, "%d ", showing);
        memshow_virtual(processes[showing].p_pagetable, s);
    }
}

// searches for a free physical page in memory and assigns it to the passed owner
// returns a pointer to the physical page, or NULL if no free page is available.

x86_64_pagetable* assign_free_page(int8_t owner) {
    for (uintptr_t addr = 0; addr < MEMSIZE_PHYSICAL; addr += PAGESIZE) {
        int pn = PAGENUMBER(addr);
        if (pageinfo[pn].refcount == 0 && pageinfo[pn].owner == PO_FREE) {
            // allocate the page
            pageinfo[pn].refcount = 1;
            pageinfo[pn].owner = owner; // set ownership to the passed owner
            memset((void*) addr, 0, PAGESIZE); // clear the page to prevent data leakage
            return (x86_64_pagetable*) addr;
        }
    }
    return NULL; // no free page available
}

// search through pageinfo array to find an unallocated page and return its addres
uintptr_t alloc_free_page(int8_t owner) {
    for (uintptr_t addr = 0; addr < MEMSIZE_PHYSICAL; addr += PAGESIZE) {
        int pn = PAGENUMBER(addr);
        if (pageinfo[pn].refcount == 0 && pageinfo[pn].owner == PO_FREE) {
            // allocate this page
            pageinfo[pn].refcount = 1;
            pageinfo[pn].owner = owner;
            // zero out the page to prevent data leakage
            memset((void*) addr, 0, PAGESIZE);
            return addr;
        }
    }
    // no free page found
    return 0;
}

// reduce ref count
// free l4 ...
// free pg itself
// return -1

void sys_exit(pid_t pid) {

    x86_64_pagetable* pt = processes[pid].p_pagetable;

    //  iterate over all virtual addresses in the process's address space
    for (uintptr_t va = PROC_START_ADDR; va < MEMSIZE_VIRTUAL; va += PAGESIZE) {
        vamapping vam = virtual_memory_lookup(pt, va);
        int pn = PAGENUMBER(vam.pa);
        if (vam.pn != -1 && (vam.perm & PTE_W)){
            // if its writtable
            if (pageinfo[pn].owner == pid){
                pageinfo[pn].refcount = 0;
                pageinfo[pn].owner = PO_FREE;                
            }
        }
        else if (vam.pn != -1 && (vam.perm & PTE_P)) {
            // if its read only
            if (pageinfo[pn].refcount > 0 && pageinfo[pn].owner > 0) {
                pageinfo[pn].refcount--;
            }
        }
    }

    x86_64_pagetable *table4 = processes[pid].p_pagetable;
    x86_64_pagetable *table3 = (x86_64_pagetable*) PTE_ADDR(table4->entry[0]);    
    x86_64_pagetable *table2 = (x86_64_pagetable*) PTE_ADDR(table3->entry[0]);
    x86_64_pagetable *table11 = (x86_64_pagetable*) PTE_ADDR(table2->entry[0]);
    x86_64_pagetable *table12 = (x86_64_pagetable*) PTE_ADDR(table2->entry[1]);

    pageinfo[PAGENUMBER(table11)].refcount = 0;
    pageinfo[PAGENUMBER(table11)].owner = PO_FREE;

    pageinfo[PAGENUMBER(table12)].refcount = 0;
    pageinfo[PAGENUMBER(table12)].owner = PO_FREE;

    pageinfo[PAGENUMBER(table2)].refcount = 0;
    pageinfo[PAGENUMBER(table2)].owner = PO_FREE;

    pageinfo[PAGENUMBER(table3)].refcount = 0;
    pageinfo[PAGENUMBER(table3)].owner = PO_FREE;    
    
    pageinfo[PAGENUMBER(table4)].refcount = 0;
    pageinfo[PAGENUMBER(table4)].owner = PO_FREE;

    // mark the current process free
    processes[pid].p_state = P_FREE;
    schedule();
}
