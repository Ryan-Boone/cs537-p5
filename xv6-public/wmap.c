#include "types.h"
#include "defs.h"
#include "param.h"
#include "memlayout.h"
#include "mmu.h"
#include "x86.h"
#include "proc.h"
#include "spinlock.h"
#include "wmap.h"
#include "fs.h"
#include "file.h"

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