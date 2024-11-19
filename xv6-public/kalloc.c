// Physical memory allocator, intended to allocate
// memory for user processes, kernel stacks, page table pages,
// and pipe buffers. Allocates 4096-byte pages.

#include "types.h"
#include "defs.h"
#include "param.h"
#include "memlayout.h"
#include "mmu.h"
#include "spinlock.h"

struct run {
  struct run *next;
};

struct {
  struct spinlock lock;
  int use_lock;
  struct run *freelist;
  char ref_cnt[PHYSTOP/PGSIZE]; //ref count for each physical page
} kmem;

void freerange(void *vstart, void *vend);
extern char end[]; // first address after kernel loaded from ELF file
                   // defined by the kernel linker script in kernel.ld


// Initialization happens in two phases.
// 1. main() calls kinit1() while still using entrypgdir to place just
// the pages mapped by entrypgdir on free list.
// 2. main() calls kinit2() with the rest of the physical pages
// after installing a full page table that maps them on all cores.
void 
kinit1(void *vstart, void *vend) {
  initlock(&kmem.lock, "kmem");
  kmem.use_lock = 0;
  freerange(vstart, vend);
}

void
kinit2(void *vstart, void *vend)
{
  freerange(vstart, vend);
  kmem.use_lock = 1;
}

void
freerange(void *vstart, void *vend)
{
  char *p;
  p = (char*)PGROUNDUP((uint)vstart);
  for(; p + PGSIZE <= (char*)vend; p += PGSIZE)
    kfree(p);
  memset(kmem.ref_cnt, 0, sizeof(kmem.ref_cnt));
}
//inc ref counts when fork or new proc opens
//dec when child writes
//dec when proc calls exit
//if count is 0, then safe to free because no other process is reading that page
//


//PAGEBREAK: 21
// Free the page of physical memory pointed at by v,
// which normally should have been returned by a
// call to kalloc().  (The exception is when
// initializing the allocator; see kinit above.)
void
kfree(char *v)
{
  struct run *r;

  if((uint)v % PGSIZE || v < end || V2P(v) >= PHYSTOP)
    panic("kfree");

  // Only free if reference count becomes 0
  if(kmem.use_lock)
    acquire(&kmem.lock);
    
  if(--kmem.ref_cnt[V2P(v)/PGSIZE] > 0) {
    if(kmem.use_lock)
      release(&kmem.lock);
    return;
  }

  // Fill with junk to catch dangling refs.
  memset(v, 1, PGSIZE);

  r = (struct run*)v;
  r->next = kmem.freelist;
  kmem.freelist = r;
  
  if(kmem.use_lock)
    release(&kmem.lock);
}


// Allocate one 4096-byte page of physical memory.
// Returns a pointer that the kernel can use.
// Returns 0 if the memory cannot be allocated.
char* 
kalloc(void) {
  struct run *r;
  if(kmem.use_lock)
    acquire(&kmem.lock);
  r = kmem.freelist;
  if(r) {
    kmem.freelist = r->next;
    kmem.ref_cnt[V2P((char*)r)/PGSIZE] = 1;  // Initialize ref count
  }
  if(kmem.use_lock)
    release(&kmem.lock);
  return (char*)r;
}

// Increment reference count for a physical page
void kincrement(char* pa) {
  if(kmem.use_lock)
    acquire(&kmem.lock);
  kmem.ref_cnt[V2P(pa)/PGSIZE]++;
  if(kmem.use_lock)
    release(&kmem.lock);
}

// Decrement reference count for a physical page
void kdecrement(char* pa) {
  if(kmem.use_lock)
    acquire(&kmem.lock);
  if(kmem.ref_cnt[V2P(pa)/PGSIZE] == 1) {
    if(kmem.use_lock)
      release(&kmem.lock);
    kfree(pa);
    return;
  }
  kmem.ref_cnt[V2P(pa)/PGSIZE]--;
  if(kmem.use_lock)
    release(&kmem.lock);
}

// Get reference count for a physical page
int kgetrefcnt(char* pa) {
  int ref;
  if(kmem.use_lock)
    acquire(&kmem.lock);
  ref = kmem.ref_cnt[V2P(pa)/PGSIZE];
  if(kmem.use_lock)
    release(&kmem.lock);
  return ref;
}


