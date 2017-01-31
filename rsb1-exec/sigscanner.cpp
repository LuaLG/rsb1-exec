#include "sigscanner.h"

// thanks booing for this
// also, we should probably consoldiate these into 1 function

int SigScanner::ScanNoAlign(char *to_find, int bcount, int reachsz, int start, int endd, int align)
{
    MEMORY_BASIC_INFORMATION mem;
    char* reach = (char*)malloc(reachsz);

    for(char* i = (char*)start;;) {
        VirtualQuery(i, &mem, sizeof(mem));
        if((mem.AllocationProtect & 238) && !(mem.Protect & 257) && (mem.State & 4096)) { // TODO: wat are theez
            char* end = (char*)mem.BaseAddress + mem.RegionSize;
            for(char* x = (char*)mem.BaseAddress; x < end;) {
                memcpy(reach, x, reachsz); // fast as fuck
                for(int ii = 0; ii < reachsz; ii += align) {
                    if(*(int*)(reach + ii) == *(int*)to_find) {
                        if (bcount == 4) return (int)x + ii;
                        char match = 1;
                        for (int b = 4; b < bcount; b++)
                            if (*(unsigned char*)(reach + ii + b) != *(unsigned char*)(to_find + b))
                                match = 0;
                        if (match) return (int)x + ii;
                    }
                }
                x += reachsz;
            }
        }
        int oldi = (int)i;
        i += mem.RegionSize;
        if (((int)i > endd - mem.RegionSize) || (oldi>(int)i))
            break;
    }
    free(reach);
    return 0;
}

int SigScanner::ScanNoAlignW(char *to_find, int bcount, int reachsz, int start, int endd, int align)
{
    MEMORY_BASIC_INFORMATION mem;
    char* reach = (char*)malloc(reachsz);

    for(char* i = (char*)start;;) {
        VirtualQuery(i, &mem, sizeof(mem));
        if((mem.AllocationProtect & 238) && !(mem.Protect & 257) && (mem.State & 4096) && (mem.Protect & WRITABLE)) {
            char* end = (char*)mem.BaseAddress + mem.RegionSize;
            for(char* x = (char*)mem.BaseAddress; x < end;) {
                memcpy(reach, x, reachsz); // fast as fuck
                for(int ii = 0; ii < reachsz; ii += align) {
                    if(*(int*)(reach + ii) == *(int*)to_find) {
                        if (bcount == 4) return (int)x + ii;
                        char match = 1;
                        for (int b = 4; b < bcount; b++)
                            if (*(unsigned char*)(reach + ii + b) != *(unsigned char*)(to_find + b))
                                match = 0;
                        if (match) return (int)x + ii;
                    }
                }
                x += reachsz;
            }
        }
        int oldi = (int)i;
        i += mem.RegionSize;
        if (((int)i > endd - mem.RegionSize) || (oldi>(int)i))
            break;
    }
    free(reach);
    return 0;
}
