#pragma once
#include "macros.h"
#include "structs.h"

//available modules
int shellcodeinjection_main(int argc, char* argv[]);
int Peinjector_main(int argc, char* argv[]);
int encryptor_main(int argc, char* argv[]);



//shellcode injection techniques

void ProcessInjection(int PID, BYTE* shellcode, size_t size);
void ThreadHijacking(DWORD PID, DWORD TID, BYTE* shellcode, size_t size);
int QueueUserAPCInjection(DWORD PID, DWORD TID, BYTE* shellcode, size_t size);
int EarlyBird(BYTE* shellcode, size_t size);
int MapViewOfSectionInjection(DWORD PID, BYTE* shellcode, size_t size);

//pe injection techniques
int ProcessHollowing(peinfos infos, char* path);
int ManualMappingDllInjection(peinfos infos, DWORD PID);
int NormalDllInjection(char* path, DWORD PID);
int LdrLoadDll_Injection(char* path, DWORD PID);


