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
            return ((_GetGlobalState) Addrs::getglobalstate)(this, stateidx);
        }
        void Spawn(int *state)
        {
            typedef void (*_spawn)(int *state);
            return ((_spawn) Addrs::spawn)(state);
        }
};
