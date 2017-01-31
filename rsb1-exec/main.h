#pragma once

#include <string>

typedef void (*_deserialize)(int *state, std::string &code, const char *chunkname, unsigned int modkey);

// write hackflag to its default value - bypasses shutdown from deserialize.
// this isn't a permanent solution (i hope).
#define RESTORE_HACKFLAG()     { int flag = (int) GetModuleHandle(0) + 0x1198310; \
                               *(int*)(flag) = 8; }

// on ScriptContext's resume, the identity is taken from state-0x14
#define SET_IDENTITY(thread, identity) *(int*)(thread-0x14) = identity