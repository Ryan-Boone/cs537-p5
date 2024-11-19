#include "types.h"
#include "param.h"
#include "memlayout.h"
#include "mmu.h"     
#include "proc.h"
#include "defs.h"    
#include "x86.h"
#include "spinlock.h"
#include "sleeplock.h"
#include "fs.h"
#include "file.h"
#include "wmap.h"

static pte_t *
walkpgdir(pde_t *pgdir, const void *va, int alloc)
{
  pde_t *pde;
  pte_t *pgtab;

  pde = &pgdir[PDX(va)];
  if(*pde & PTE_P){
    pgtab = (pte_t*)P2V(PTE_ADDR(*pde));
  } else {
    if(!alloc || (pgtab = (pte_t*)kalloc()) == 0)
      return 0;
    // Make sure all those PTE_P bits are zero.
    memset(pgtab, 0, PGSIZE);
    // The permissions here are overly generous, but they can
    // be further restricted by the permissions in the page table
    // entries, if necessary.
    *pde = V2P(pgtab) | PTE_P | PTE_W | PTE_U;
  }
  return &pgtab[PTX(va)];
}

static int
mappages(pde_t *pgdir, void *va, uint size, uint pa, int perm)
{
  char *a, *last;
  pte_t *pte;

  a = (char*)PGROUNDDOWN((uint)va);
  last = (char*)PGROUNDDOWN(((uint)va) + size - 1);
  for(;;){
    if((pte = walkpgdir(pgdir, a, 1)) == 0)
      return -1;
    if(*pte & PTE_P)
      panic("remap");
    *pte = pa | perm | PTE_P;
    if(a == last)
      break;
    a += PGSIZE;
    pa += PGSIZE;
  }
  return 0;
}

// Helper function to find a mapping by address
static struct wmap_struct*
find_mapping(struct proc *p, uint addr)
{
    int i;
    for(i = 0; i < MAX_WMMAP_INFO; i++) {
        if(p->wmaps[i].allocated && p->wmaps[i].addr == addr) {
            return &p->wmaps[i];
        }
    }
    return 0;
}

// Helper function to write pages back to file
static int
write_pages_to_file(struct wmap_struct *wmap)
{
    struct file *f = wmap->f;
    uint addr;
    int bytes_written = 0;

    if(!f || !f->ip)
        return -1;

    // Write each mapped page back to the file
    for(addr = wmap->addr; addr < wmap->addr + wmap->length; addr += PGSIZE) {
        pte_t *pte = walkpgdir(myproc()->pgdir, (char*)addr, 0);
        if(pte && (*pte & PTE_P) && (*pte & PTE_W)) {  // If page is present and writable
            char *va = P2V(PTE_ADDR(*pte));
            int n;
            
            begin_op();
            ilock(f->ip);
            
            // Write the page contents back to file
            n = writei(f->ip, va, bytes_written, PGSIZE);
            
            iunlock(f->ip);
            end_op();
            
            if(n < 0)
                return -1;
                
            bytes_written += n;
        }
    }
    return SUCCESS;
}

int
sys_wunmap(void)
{
    uint addr;
    struct proc *p = myproc();
    struct wmap_struct *wmap;

    // Get the address argument
    if(argint(0, (int*)&addr) < 0)
        return FAILED;

    // Address must be page-aligned
    if(addr % PGSIZE != 0)
        return FAILED;

    // Find the mapping
    wmap = find_mapping(p, addr);
    if(!wmap)
        return FAILED;

    // If this is a file mapping and MAP_SHARED is set, write changes back
    if(wmap->f && (wmap->flags & MAP_SHARED)) {
        if(write_pages_to_file(wmap) < 0)
            return FAILED;
    }

    // Free all allocated pages in this mapping
    uint curr_addr;
    for(curr_addr = wmap->addr; 
        curr_addr < wmap->addr + wmap->length; 
        curr_addr += PGSIZE) {
        
        pte_t *pte = walkpgdir(p->pgdir, (char*)curr_addr, 0);
        if(pte && (*pte & PTE_P)) {
            char *v = P2V(PTE_ADDR(*pte));
            kfree(v);
            *pte = 0;  // Clear the PTE
        }
    }

    // If this was a file mapping, close the file
    if(wmap->f) {
        fileclose(wmap->f);
        wmap->f = 0;
    }

    // Clear the mapping
    wmap->allocated = 0;
    wmap->addr = 0;
    wmap->length = 0;
    wmap->flags = 0;
    wmap->fd = -1;
    wmap->num_pages = 0;
    
    p->num_wmaps--;

    return SUCCESS;
}

// Helper function to check if address range is free
static int
is_range_free(struct proc *p, uint addr, int length)
{
    int i;
    uint end = addr + length;
    
    // Check if range is within allowed bounds
    if (addr < 0x60000000 || end > 0x80000000)
        return 0;
        
    // Check for overlap with existing mappings
    for (i = 0; i < 16; i++) {
        if (!p->wmaps[i].allocated)
            continue;
            
        uint map_end = p->wmaps[i].addr + p->wmaps[i].length;
        if ((addr >= p->wmaps[i].addr && addr < map_end) ||
            (end > p->wmaps[i].addr && end <= map_end))
            return 0;
    }
    
    return 1;
}

// Helper function to find free wmap slot
static struct wmap_struct*
find_free_wmap(struct proc *p)
{
    int i;
    for (i = 0; i < 16; i++) {
        if (!p->wmaps[i].allocated)
            return &p->wmaps[i];
    }
    return 0;
}

// Page fault handler for lazy allocation
int
handle_wmap_fault(struct proc *p, uint addr)
{
    int i;
    struct wmap_struct *wmap = 0;
    
    // Find which mapping this address belongs to
    for (i = 0; i < 16; i++) {
        if (!p->wmaps[i].allocated)
            continue;
            
        if (addr >= p->wmaps[i].addr && 
            addr < p->wmaps[i].addr + p->wmaps[i].length) {
            wmap = &p->wmaps[i];
            break;
        }
    }
    
    if (!wmap)
        return 0;  // Not our fault to handle
        
    // Calculate page-aligned address
    uint page_addr = PGROUNDDOWN(addr);
    
    // Allocate new page
    char *mem = kalloc();
    if (!mem)
        return -1;
    
    memset(mem, 0, PGSIZE);
    
    // If file-backed, read from file
    if (!(wmap->flags & MAP_ANONYMOUS) && wmap->f) {
        uint offset = page_addr - wmap->addr;
        ilock(wmap->f->ip);
        readi(wmap->f->ip, mem, offset, PGSIZE);
        iunlock(wmap->f->ip);
    }
    
    // Map the page
    if (mappages(p->pgdir, (void*)page_addr, PGSIZE, V2P(mem), 
                PTE_W|PTE_U) < 0) {
        kfree(mem);
        return -1;
    }
    
    wmap->num_pages++;
    return 1;
}
int
sys_getwmapinfo(void)
{
    struct wmapinfo *wminfo;
    struct proc *p = myproc();
    int i;
    
    if(argptr(0, (char**)&wminfo, sizeof(*wminfo)) < 0)
        return -1;
        
    wminfo->total_mmaps = p->num_wmaps;
    
    for(i = 0; i < MAX_WMMAP_INFO; i++) {
        if(p->wmaps[i].allocated) {
            wminfo->addr[i] = p->wmaps[i].addr;
            wminfo->length[i] = p->wmaps[i].length;
            wminfo->n_loaded_pages[i] = p->wmaps[i].num_pages;
        } else {
            wminfo->addr[i] = 0;
            wminfo->length[i] = 0;
            wminfo->n_loaded_pages[i] = 0;
        }
    }
    
    return 0;
}

int
sys_wmap(void)
{
    uint addr;
    int length, flags, fd;
    struct proc *p = myproc();
    
    // Get arguments
    if (argint(1, &length) < 0 || argint(2, &flags) < 0 || 
        argint(3, &fd) < 0 || argptr(0, (void*)&addr, sizeof(addr)) < 0)
        return FAILED;
    
    // Validate arguments
    if (length <= 0)
        return FAILED;
        
    // Must have MAP_SHARED and MAP_FIXED
    if (!(flags & MAP_SHARED) || !(flags & MAP_FIXED))
        return FAILED;
        
    // Check alignment
    if (addr % PGSIZE != 0)
        return FAILED;
        
    // Round length up to page size
    length = PGROUNDUP(length);
    
    // Check if address range is available
    if (!is_range_free(p, addr, length))
        return FAILED;
    
    // Find free wmap slot
    struct wmap_struct *wmap = find_free_wmap(p);
    if (!wmap)
        return FAILED;
    
    // Set up the mapping
    wmap->addr = addr;
    wmap->length = length;
    wmap->flags = flags;
    wmap->fd = fd;
    wmap->allocated = 1;
    wmap->num_pages = 0;
    
    // Handle file-backed mapping
    if (!(flags & MAP_ANONYMOUS)) {
        if (fd < 0 || fd >= NOFILE || !p->ofile[fd])
            return FAILED;
            
        wmap->f = p->ofile[fd];
        filedup(wmap->f);  // Increment reference count
    } else {
        wmap->f = 0;
    }
    
    p->num_wmaps++;
    return addr;
}