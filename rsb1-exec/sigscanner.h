#pragma once
#include <windows.h>

#define WRITABLE (PAGE_READWRITE | PAGE_WRITECOPY |PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)

class SigScanner {
    public:
        static int ScanNoAlign(char *to_find, int bcount, int reachsz = 1024, int start = 0, int endd = 0x50000000, int align = 1);
        static int ScanNoAlignW(char *to_find, int bcount, int reachsz = 1024, int start = 0, int endd = 0x50000000, int align = 1);
};
