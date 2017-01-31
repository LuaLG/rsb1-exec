#include "scans.h"
#include "sigscanner.h"

int Addrs::deserialize = 0;
int Addrs::spawn = 0;
int Addrs::getglobalstate = 0;

void start_scans()
{
    int base = (int) GetModuleHandle(0);
    Addrs::deserialize = (SigScanner::ScanNoAlign("\x43\x02\x44\x0D\xE4", 5) - 0x17C); // 43 02 44 0D E4
    Addrs::getglobalstate = SigScanner::ScanNoAlign((char*) "\x55\x8B\xEC\x56\x57\x6A\x05", 7); // 55 8B EC 56 57 6A 05
    Addrs::spawn = base + 0xECDC0; // TODO: get a sig
}