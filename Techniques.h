#pragma once
#include "macros.h"
#include "structs.h"


void ProcessInjection(int PID, BYTE* shellcode, size_t size);
int shellcodeinjection_main(int argc,char* argv[]);
void ThreadHijacking(DWORD PID, DWORD TID, BYTE* shellcode, size_t size);
int QueueUserAPCInjection(DWORD PID, DWORD TID, BYTE* shellcode, size_t size);
int EarlyBird(BYTE* shellcode, size_t size);
int MapViewOfSectionInjection(DWORD PID, BYTE* shellcode, size_t size);
int ProcessHollowing(peinfos infos, char* path);
int peinjector_main(int argc, char* argv[]);


