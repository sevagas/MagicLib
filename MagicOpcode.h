#pragma once

#ifndef opcode_h
#define opcode_h

/* Some includes */
#include "Magic.h"


extern BYTE* JMP_RCX_OPCODE;
extern BYTE* JMP_0_OPCODE;
#ifdef _WIN64
extern BYTE* JMP_RAX_OPCODE;
extern BYTE* MOV_PTRRDX_RAX_RET;
#else
extern BYTE* CALL_EAX_OPCODE;
extern BYTE* JMP_EAX_OPCODE;
#endif


#endif