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
        pte_t *pte = getwalkpgdir(myproc()->pgdir, (char*)addr, 0);
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
        
        pte_t *pte = getwalkpgdir(p->pgdir, (char*)curr_addr, 0);
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
    for (i = 0; i < MAX_WMMAP_INFO; i++) {
        if (!p->wmaps[i].allocated)
            continue;
            
        uint map_start = p->wmaps[i].addr;
        uint map_end = map_start + p->wmaps[i].length;
        
        // Debug prints
        cprintf("Checking overlap: new(0x%x-0x%x) vs existing(0x%x-0x%x)\n",
                addr, end, map_start, map_end);
        
        // Check for any overlap:
        // 1. New region starts inside existing region
        // 2. New region ends inside existing region
        // 3. New region completely contains existing region
        if ((addr >= map_start && addr < map_end) ||          // Start overlaps
            (end > map_start && end <= map_end) ||            // End overlaps
            (addr <= map_start && end >= map_end)) {          // Complete overlap
            cprintf("Overlap detected!\n");
            return 0;
        }
    }
    
    cprintf("Range 0x%x-0x%x is free\n", addr, end);
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
    if (getmappages(p->pgdir, (void*)page_addr, PGSIZE, V2P(mem), 
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
        
    // Set total number of active mappings
    wminfo->total_mmaps = p->num_wmaps;
    
    // Clear all entries first
    for(i = 0; i < MAX_WMMAP_INFO; i++) {
        wminfo->addr[i] = 0;
        wminfo->length[i] = 0;
        wminfo->n_loaded_pages[i] = 0;
    }
    
    // Copy only active mappings
    int map_idx = 0;
    for(i = 0; i < MAX_WMMAP_INFO; i++) {
        if(p->wmaps[i].allocated) {
            wminfo->addr[map_idx] = p->wmaps[i].addr;
            wminfo->length[map_idx] = p->wmaps[i].length;
            wminfo->n_loaded_pages[map_idx] = p->wmaps[i].num_pages;
            map_idx++;
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
    int addr_val;
    if(argint(0, &addr_val) < 0 ||
       argint(1, &length) < 0 ||
       argint(2, &flags) < 0 ||
       argint(3, &fd) < 0) {
        cprintf("sys_wmap: Failed to get arguments\n");
        return FAILED;
    }
    
    addr = (uint)addr_val;
    
    // Validate arguments
    if (length <= 0) {
        cprintf("sys_wmap: Invalid length %d\n", length);
        return FAILED;
    }
    
    // Must have both MAP_FIXED and MAP_SHARED
    if ((flags & (MAP_FIXED | MAP_SHARED)) != (MAP_FIXED | MAP_SHARED)) {
        cprintf("sys_wmap: Invalid flags 0x%x\n", flags);
        return FAILED;
    }
    
    // Check alignment
    if (addr % PGSIZE != 0) {
        cprintf("sys_wmap: Address not page aligned 0x%x\n", addr);
        return FAILED;
    }
    
    // Round length up to page size for internal use
    int rounded_length = PGROUNDUP(length);
    
    cprintf("sys_wmap: Checking range addr=0x%x len=%d\n", addr, rounded_length);
    
    // Validate address range
    if (!is_range_free(p, addr, rounded_length)) {
        cprintf("sys_wmap: Address range not free\n");
        return FAILED;
    }
    
    // Find free wmap slot
    struct wmap_struct *wmap = find_free_wmap(p);
    if (!wmap) {
        cprintf("sys_wmap: No free slots\n");
        return FAILED;
    }

    // Initialize the mapping completely
    memset(wmap, 0, sizeof(*wmap));  // Clear structure first
    wmap->addr = addr;
    wmap->length = length;
    wmap->flags = flags;
    wmap->allocated = 1;  // Make sure this is set
    wmap->num_pages = 0;
    
    // Handle file-backed vs anonymous mapping
    if (flags & MAP_ANONYMOUS) {
        // For anonymous mappings, ignore the fd value
        wmap->f = 0;
        wmap->fd = -1;  // Store -1 internally for anonymous mappings
    } else {
        // For file-backed mappings
        if (fd < 0 || fd >= NOFILE || !p->ofile[fd]) {
            cprintf("sys_wmap: Invalid fd %d for file mapping\n", fd);
            return FAILED;
        }
        wmap->f = p->ofile[fd];
        wmap->fd = fd;
        filedup(wmap->f);
    }
    
    p->num_wmaps++;
    
    cprintf("Created mapping: addr=0x%x, length=0x%x, flags=0x%x\n", 
            wmap->addr, wmap->length, wmap->flags);
            
    return addr;
}


