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

    Addrs::rets[0] = base + 0xB18ADF; // C3
    Addrs::rets[1] = base + 0x5B38E6; // 83 C4 04 C3
    Addrs::rets[2] = base + 0xB18D4;  // 83 C4 08 C3
    Addrs::rets[3] = base + 0x660BD0; // 83 C4 0C C3
    Addrs::rets[4] = base + 0x83E6DC; // 83 C4 10 C3

    Addrs::deserialize = (SigScanner::ScanNoAlign("\x43\x02\x44\x0D\xE4", 5) - 0x17C); // 43 02 44 0D E4
    Addrs::getglobalstate = SigScanner::ScanNoAlign((char*) "\x55\x8B\xEC\x56\x57\x6A\x05", 7); // 55 8B EC 56 57 6A 05
    Addrs::newthread = (SigScanner::ScanNoAlign("\x51\x56\x8B\x75\x08\x57\x8B\x4E\x08\x8B\x44\x31\x60\x3B\x44\x31\x54", 17) - 24); //51 56 8B 75 08 57 8B 4E 08 8B 44 31 60 3B 44 31 54
    Addrs::spawn = base + 0xECDC0; // TODO: get a sig
}