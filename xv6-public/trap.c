#include "types.h"
#include "defs.h"
#include "param.h"
#include "memlayout.h"
#include "mmu.h"
#include "proc.h"
#include "x86.h"
#include "traps.h"
#include "spinlock.h"
#include "wmap.h"
#include "fs.h"
#include "sleeplock.h"
#include "file.h"

// Interrupt descriptor table (shared by all CPUs).
struct gatedesc idt[256];
extern uint vectors[];  // in vectors.S: array of 256 entry pointers
struct spinlock tickslock;
uint ticks;

void
tvinit(void)
{
  int i;

  for(i = 0; i < 256; i++)
    SETGATE(idt[i], 0, SEG_KCODE<<3, vectors[i], 0);
  SETGATE(idt[T_SYSCALL], 1, SEG_KCODE<<3, vectors[T_SYSCALL], DPL_USER);

  initlock(&tickslock, "time");
}

void
idtinit(void)
{
  lidt(idt, sizeof(idt));
}

//PAGEBREAK: 41
void
trap(struct trapframe *tf)
{
  if(tf->trapno == T_SYSCALL){
    if(myproc()->killed)
      exit();
    myproc()->tf = tf;
    syscall();
    if(myproc()->killed)
      exit();
    return;
  }

  switch(tf->trapno){
  case T_PGFLT:
    int valid_addr = 0;
    int failed_addr = rcr2();
    //struct wmapinfo wmap = myproc()->mmap;
    //struct wmap_struct wmap[16] = myproc()->wmaps;

    pte_t *pgdir = myproc()->pgdir;

    int cow_va = PGROUNDDOWN(failed_addr);
    pte_t *cow_pte = getwalkpgdir(pgdir, (void *)cow_va, 0);
    //Check first of the addr is previously written bit
    if(*cow_pte != 0 && (*cow_pte & PTE_P) != 0 && (*cow_pte & PTE_PW) != 0)
    {
      //Check the reference count
      int cow_pa = PTE_ADDR(*cow_pte);
      if(get_ref_count(cow_pa) > 1)
      { 
        //Make a new page 
        char *mem = kalloc();
        if(mem == 0)
        {
          //KILL PROCESS
          kill(myproc()->pid);
        }
        *cow_pte &= ~PTE_P;
        *cow_pte |= PTE_W;
        uint flags = PTE_FLAGS(*cow_pte);
        //copy contents from cow_va to mem
        memmove(mem, (char*)P2V(cow_pa), PGSIZE);
        //Putting new page into processes pgdir
        if(getmappages(pgdir, (void*)cow_va, PGSIZE, V2P(mem), flags) != 0)
        {
          //Kill process
          kill(myproc()->pid);
        }
        dec_ref(cow_pa);
        lcr3(V2P(pgdir));
      }
      else //No other reference than the current page so no need to copy the current page
      {
        *cow_pte |= PTE_W;
        lcr3(V2P(pgdir)); 
      }
      valid_addr = 1;
    }

    

    for (int i = 0; i < MAX_WMMAP_INFO; i++) {
      if (myproc()->wmaps[i].addr != 0 && failed_addr >= myproc()->wmaps[i].addr && failed_addr < (myproc()->wmaps[i].addr + myproc()->wmaps[i].length)) {
        //alloc ONE page if addr is in range of one of the mappings
        char *mem = kalloc();
        if (mem == 0) {
          // Kill process or do something idk
          kill(myproc()->pid);
        }

        int page_start = (failed_addr % PGSIZE == 0) ? failed_addr : failed_addr - (failed_addr % PGSIZE);
        if(getmappages(pgdir, (void*)(page_start), PGSIZE, V2P(mem), PTE_W | PTE_U) != 0) {
          // Kill process or do something idk
          kill(myproc()->pid);
        }

        if (!myproc()->wmaps[i].f) {
          // in anon set memory to zero
          memset((void *)page_start, 0, PGSIZE);
        } else  {
          // in fb set memory to file content

          // calculate offest within file for read
          uint off = page_start - myproc()->wmaps[i].addr;
          
          // reading 1 PAGE from file into page_start starting read at offset
          ilock(myproc()->wmaps[i].f->ip);                                                   //TODO: something wrong here?
          int size = readi(myproc()->wmaps[i].f->ip, (char *)page_start, off, PGSIZE);
          iunlock(myproc()->wmaps[i].f->ip);

          // check if readi was successful
          if (size == -1) {
            kill(myproc()->pid);
          }
        }

        myproc()->wmaps[i].num_pages++;                                                     // TODO: here
        valid_addr = 1;
        break;
      }  
    }

    if (valid_addr != 1) {
      // print out segfault if no mappings are found for address and kill process
      cprintf("Segmentation Fault\n");
      kill(myproc()->pid);
    }

    lapiceoi();
    break;
  case T_IRQ0 + IRQ_TIMER:
    if(cpuid() == 0){
      acquire(&tickslock);
      ticks++;
      wakeup(&ticks);
      release(&tickslock);
    }
    lapiceoi();
    break;
  case T_IRQ0 + IRQ_IDE:
    ideintr();
    lapiceoi();
    break;
  case T_IRQ0 + IRQ_IDE+1:
    // Bochs generates spurious IDE1 interrupts.
    break;
  case T_IRQ0 + IRQ_KBD:
    kbdintr();
    lapiceoi();
    break;
  case T_IRQ0 + IRQ_COM1:
    uartintr();
    lapiceoi();
    break;
  case T_IRQ0 + 7:
  case T_IRQ0 + IRQ_SPURIOUS:
    cprintf("cpu%d: spurious interrupt at %x:%x\n",
            cpuid(), tf->cs, tf->eip);
    lapiceoi();
    break;

  //PAGEBREAK: 13
  default:
    if(myproc() == 0 || (tf->cs&3) == 0){
      // In kernel, it must be our mistake.
      cprintf("unexpected trap %d from cpu %d eip %x (cr2=0x%x)\n",
              tf->trapno, cpuid(), tf->eip, rcr2());
      panic("trap");
    }
    // In user space, assume process misbehaved.
    cprintf("pid %d %s: trap %d err %d on cpu %d "
            "eip 0x%x addr 0x%x--kill proc\n",
            myproc()->pid, myproc()->name, tf->trapno,
            tf->err, cpuid(), tf->eip, rcr2());
    myproc()->killed = 1;
  }

  // Force process exit if it has been killed and is in user space.
  // (If it is still executing in the kernel, let it keep running
  // until it gets to the regular system call return.)
  if(myproc() && myproc()->killed && (tf->cs&3) == DPL_USER)
    exit();

  // Force process to give up CPU on clock tick.
  // If interrupts were on while locks held, would need to check nlock.
  if(myproc() && myproc()->state == RUNNING &&
     tf->trapno == T_IRQ0+IRQ_TIMER)
    yield();

  // Check if the process has been killed since we yielded
  if(myproc() && myproc()->killed && (tf->cs&3) == DPL_USER)
    exit();
}
