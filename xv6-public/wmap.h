#ifndef _WMAP_H_
#define _WMAP_H_

// Required flags for wmap
#define MAP_SHARED    0x0002
#define MAP_ANONYMOUS 0x0004
#define MAP_FIXED    0x0008

// Return values
#define FAILED -1
#define SUCCESS 0

// Maximum number of memory mappings
#define MAX_WMMAP_INFO 16

// Structure for wmapinfo system call
struct wmapinfo {
    int total_mmaps;                    // Total number of wmap regions
    int addr[MAX_WMMAP_INFO];           // Starting address of mapping
    int length[MAX_WMMAP_INFO];         // Size of mapping
    int n_loaded_pages[MAX_WMMAP_INFO]; // Number of pages physically loaded into memory
};

// Function declarations for user programs
uint wmap(uint addr, int length, int flags, int fd);
int wunmap(uint addr);
uint va2pa(uint va);
int getwmapinfo(struct wmapinfo *wminfo);

#endif // _WMAP_H_