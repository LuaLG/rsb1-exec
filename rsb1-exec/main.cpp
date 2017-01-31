#include "main.h"
#include <stdio.h>
#include <windows.h>
#include <fstream>
#include <sstream>
#include <vector>
#include <iostream>
#include "scriptcontext.h"
#include "sigscanner.h"
#include "scans.h"

// set first instruction of FreeConsole to ret, causing it to do nothing
// ROBLOX has a thread which constantly calls FreeConsole just to inconvenience us. lol.
void enable_console()
{
    int *addr = (int*) GetProcAddress(GetModuleHandle("kernel32.dll"), "FreeConsole");
    DWORD oldp;
    VirtualProtect(addr, 1, PAGE_EXECUTE_READWRITE, &oldp);
    *addr = 0xC3;
    VirtualProtect(addr, 1, oldp, &oldp);
}

// TODO: split this up into different functions
void init()
{
    enable_console();
    AllocConsole();
    freopen("conin$", "r+t", stdin);
    freopen("conout$", "w+t", stdout);
    freopen("conout$", "w+t", stderr);
    SetConsoleTitle("rsb1-exec");

    int base = (int) GetModuleHandle(0);
    int sc_vtable = (base + 0xD8DAAC);
    ScriptContext *scriptContext;
    do {
        scriptContext = (ScriptContext*) SigScanner::ScanNoAlignW((char*) &sc_vtable, 4);
        Sleep(1000);
    } while(!scriptContext);

    start_scans();

    std::string loc;
    printf("file path: ");
    std::getline(std::cin, loc);

    // read it from a file
    std::ifstream file(loc, std::ios::binary);
    if(!file.is_open()) {
        printf("error opening file\n");
        return;
    }

    std::stringstream buff;
    buff << file.rdbuf();
    std::string code(buff.str());
    file.close();
    printf("len: %d\n", code.length());

    _deserialize deserialize = (_deserialize) Addrs::deserialize;
    // it can just be int*, no need to include Lua in this project.
    int *g_state = scriptContext->GetGlobalState(1);
    deserialize(g_state, code, "a", scriptContext->GetCoreScriptModKey());
    RESTORE_HACKFLAG();
    printf("done\n");
    SET_IDENTITY(g_state, 7); // doesn't work ??
    scriptContext->Spawn(g_state);
}

BOOL APIENTRY DllMain(HINSTANCE inst, DWORD reason, LPVOID reserved)
{
    if(reason == DLL_PROCESS_ATTACH) {
        CreateThread(0, 0, (LPTHREAD_START_ROUTINE) init, 0, 0, 0);
    }

    return 1;
}
