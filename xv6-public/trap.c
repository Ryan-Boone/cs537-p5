#include "types.h"
#include "defs.h"
#include "param.h"
#include "memlayout.h"
#include "mmu.h"
#include "proc.h"
#include "x86.h"
#include "traps.h"
#include "spinlock.h"

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
  case T_PGFLT: {
      uint va = rcr2();  // Get the faulting address
      struct proc *p = myproc();
      pte_t *pte;
      uint pa;
      char *mem;
      // First check if address is in kernel space or otherwise invalid
      if(va >= KERNBASE || va < 0) {
          cprintf("Segmentation fault\n");
          p->killed = 1;
          break;
      }
      // First try handling wmap fault
      int wmap_result = handle_wmap_fault(p, va);
      if (wmap_result > 0) {
          break;  // Successfully handled wmap fault
      }

      // If not a wmap fault, check if it's a COW fault
      if ((pte = walkpgdir(p->pgdir, (void*)va, 0)) == 0 ||
          !(*pte & PTE_P) || !(*pte & PTE_COW)) {
          // Not a COW page - real segfault
          cprintf("Segmentation fault\n");
          p->killed = 1;
          break;
      }

      // Handle COW fault
      pa = PTE_ADDR(*pte);
      
      // If refcount is 1, just make it writable
      if (get_refcount((char*)P2V(pa)) == 1) {
          if (*pte & PTE_W_OLD) {
              *pte |= PTE_W;         // Make writable
              *pte &= ~PTE_COW;      // Clear COW flag
              lcr3(V2P(p->pgdir));   // Flush TLB
              break;
          }
      }
      
      // Need to copy the page
      if ((mem = kalloc()) == 0) {
          cprintf("Page fault - out of memory\n");
          p->killed = 1;
          break;
      }

      memmove(mem, (char*)P2V(pa), PGSIZE);
      
      // Update PTE to point to new page
      *pte = V2P(mem) | PTE_P | PTE_U;
      if (*pte & PTE_W_OLD)
          *pte |= PTE_W;
          
      dec_refcount((char*)P2V(pa));
      lcr3(V2P(p->pgdir));
      break;
  }
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
