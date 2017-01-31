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


_deserialize deserialize; // ew global.. jk this isn't bad

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

// thanks booing 4 help!
// sad to make this public :(
__declspec(naked) int spoof_retaddr(int func_addr, int nargs, int *arg_buffer, int *retss)
{
    __asm {
        push ebp
        mov ebp, esp

        pushad

        mov edx, [nargs]

        mov eax, [arg_buffer]
        xor ecx, ecx

        push real_return

        lupe:
        mov ebx, [eax+ecx*4]
        push ebx
        inc ecx
        cmp ecx, edx
        jne lupe

        mov eax, [retss]
        mov eax, [eax+edx*4]
        push eax
        mov eax, [func_addr]
        jmp eax

        real_return:
        mov [ebp-0x50], eax // ew
        popad
        mov eax, [ebp-0x50]
        pop ebp
        ret
    }
}

void execute(int *state, ScriptContext *scriptContext, const char *name, std::string code)
{
    int args[] = {(int) state};
    int *nstate = (int*) spoof_retaddr(Addrs::newthread, 1, args, Addrs::rets);
    deserialize(nstate, code, name, scriptContext->GetCoreScriptModKey());
    RESTORE_HACKFLAG();
    // SET_IDENTITY(g_state, 7); // doesn't work ??
    scriptContext->Spawn(nstate);
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
    deserialize = (_deserialize) Addrs::deserialize;

    // it can just be int*, no need to include Lua in this project.
    int *g_state = scriptContext->GetGlobalState(1);

    std::string loc;
    std::stringstream buff;
    while(true) {
        printf("file path: ");
        std::getline(std::cin, loc);

        // read it from a file
        std::ifstream file(loc, std::ios::binary);
        if(!file.is_open()) {
            printf("error opening file\n");
            continue;
        }

        buff << file.rdbuf();
        std::string code(buff.str());
        file.close();
        printf("len: %d\n", code.length());
        execute(g_state, scriptContext, loc.c_str(), code);
        buff.str(std::string());
        printf("done\n");
    }
}

BOOL APIENTRY DllMain(HINSTANCE inst, DWORD reason, LPVOID reserved)
{
    if(reason == DLL_PROCESS_ATTACH) {
        CreateThread(0, 0, (LPTHREAD_START_ROUTINE) init, 0, 0, 0);
    }

    return 1;
}
