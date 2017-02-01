#include "scans.h"
#include "sigscanner.h"

int Addrs::deserialize = 0;
int Addrs::spawn = 0;
int Addrs::getglobalstate = 0;
int Addrs::newthread = 0;
int Addrs::rets[4] = { 0 };

void start_scans()
{
    int base = (int) GetModuleHandle(0);

    // we only need 1 arg right now...
    // TODO: sig these
    Addrs::rets[1] = base + 0x5EEFF6; // 83 C4 04 C3

    Addrs::deserialize = base + 0x5E80; // TODO: sig
    Addrs::getglobalstate = SigScanner::ScanNoAlign((char*) "\x55\x8B\xEC\x56\x57\x6A\x05", 7); // 55 8B EC 56 57 6A 05 
    Addrs::newthread = (SigScanner::ScanNoAlign("\x51\x56\x8B\x75\x08\x57\x8B\x4E\x08\x8B\x44\x31\x60\x3B\x44\x31\x54", 17) - 0x18); //51 56 8B 75 08 57 8B 4E 08 8B 44 31 60 3B 44 31 54
    Addrs::spawn = base + 0xEAFD0; // TODO: get a sig
}
