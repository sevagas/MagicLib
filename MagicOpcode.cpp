#include "Magic.h"


BYTE* JMP_RCX_OPCODE = (BYTE*)"\xff\xe1";
BYTE* JMP_0_OPCODE = (BYTE*)"\xeb\xfe";
#ifdef _WIN64
BYTE* JMP_RAX_OPCODE = (BYTE*)"\xff\xe0";
/*
python ROPgadget.py --binary C:\Windows\System32\ntdll.dll
0x000000018005de0a : mov qword ptr [rdx], rax ; ret
-> 00007FFC209DDE0A  48 89 02 C3 B8 0D 00 00 C0 C3 CC CC CC CC CC CC  H..ц╦...юцлллллл


*/
BYTE* MOV_PTRRDX_RAX_RET = (BYTE*)"\x48\x89\x02\xC3";
#else
BYTE* CALL_EAX_OPCODE = (BYTE*)"\xff\xd0";
BYTE* JMP_EAX_OPCODE = (BYTE*)"\xff\xe0";
#endif

