#pragma once

#include <stdio.h>
#include <Windows.h>
#include <stdlib.h>
#include <time.h>
#include <bcrypt.h>
#include "macros.h"
#include "Encryption.h"

#pragma comment(lib, "bcrypt.lib")


typedef INT(__stdcall* dllmain)(HMODULE, DWORD, LPVOID);
typedef HMODULE(__stdcall* pLoadLibraryA)(LPCSTR);
typedef FARPROC(__stdcall* pGetProcAddress)(HMODULE, LPCSTR);


//used in the manual mapping technique, served for the loader
typedef struct DllInfos
{
    PIMAGE_NT_HEADERS NtHeaders;
    BYTE* remoteBase;
    PIMAGE_IMPORT_DESCRIPTOR ImportDirectory;
    pLoadLibraryA fnLoadLibraryA;
    pGetProcAddress fnGetProcAddress;
}DllInfos;



typedef struct shellcodeinfos
{
	BYTE* shellcode;
	size_t size;

}shellcodeinfos;
 
typedef struct peinfos
{
    BYTE* pe;
    size_t size;
    IMAGE_DOS_HEADER* dosHeader;
    IMAGE_NT_HEADERS64* ntHeader;
    IMAGE_SECTION_HEADER* sectionHeader;
    IMAGE_BASE_RELOCATION* baseReloc; 
}peinfos;

typedef struct unmapndheader {
    PIMAGE_NT_HEADERS64 ntHeader;
    BYTE* NewAllocatedSpace;
}unmapndheader;

typedef struct __PROCESS_BASIC_INFORMATION {
    PVOID Reserved1;
    PVOID PebBaseAddress;
    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
    PVOID Reserved3;
} _PROCESS_BASIC_INFORMATION;
typedef enum _PROCESSINFOCLASS {
    ProcessBasicInformation = 0,
    ProcessDebugPort = 7,
    ProcessWow64Information = 26,
    ProcessImageFileName = 27,
    ProcessBreakOnTermination = 29
} PROCESSINFOCLASS;
typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING;
typedef UNICODE_STRING* PUNICODE_STRING;
typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES;



typedef OBJECT_ATTRIBUTES* POBJECT_ATTRIBUTES;


//nt functions used
typedef NTSTATUS(NTAPI* NtCreateSection_t)(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PLARGE_INTEGER MaximumSize, ULONG SectionPageProtection, ULONG AllocationAttributes, HANDLE FileHandle);
typedef NTSTATUS(NTAPI* NtmapViewOfSection_t)(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, ULONG InheritDisposition, ULONG AllocationType, ULONG Protect);
typedef NTSTATUS(NTAPI* NtQueryInformationProcess_t)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* NtUnmapViewOfSection_t)(HANDLE ProcessHandle, PVOID  BaseAddress);
typedef NTSTATUS(NTAPI* pLdrLoadDll)(PWCHAR pathToFile OPTIONAL,ULONG flags OPTIONAL,PUNICODE_STRING moduleFileName,PHANDLE moduleHandle );
typedef NTSTATUS(NTAPI* LdrpLoadDll_t)(IN PWSTR DllPath OPTIONAL, IN PUNICODE_STRING DllName, OUT PVOID* BaseAddress, IN BOOLEAN CallInit, IN BOOLEAN Redirected, IN HANDLE ParentActCtx);
typedef VOID(NTAPI* RtlInitUnicodeString_t)(PUNICODE_STRING DestinationString, PCWSTR SourceString);


typedef struct LDR_DATA
{
    pLdrLoadDll LdrLoadDll_addr;
    UNICODE_STRING path;


}LDR_DATA;