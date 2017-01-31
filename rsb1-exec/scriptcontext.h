#include "sigscanner.h"
#include "scans.h"

// roblox makes so much shit static, so we can't just use the vftbl to find shit.
class ScriptContext {
    public:
        int GetCoreScriptModKey()
        {
            return *(int*) (this + 760);
        }
        void SetCoreScriptModKey(int key)
        {
            *(int*) (this + 760) = key;
        }
        int* GetGlobalState(int stateidx)
        {
            typedef int* (__thiscall *_GetGlobalState)(ScriptContext*, int);
            // _GetGlobalState ggs = (_GetGlobalState) SigScanner::ScanNoAlign((char*) "\x55\x8B\xEC\x56\x57\x6A\x05", 7);
            // return ggs(this, stateidx);
            return ((_GetGlobalState) Addrs::getglobalstate)(this, stateidx);
        }
        void Spawn(int *state)
        {
            typedef void (*_spawn)(int *state);
            return ((_spawn) Addrs::spawn)(state);
        }
};
