#include "macros.h"
#include "structs.h"
#include "techniques.h"



peinfos ReadPeFile(char* path)
{
	peinfos infos;
	FILE* fp = fopen(path, "rb");
	if (fp == NULL) {
		error("Failed to open PE");
	}

	fseek(fp, 0, SEEK_END);
	size_t size = ftell(fp);
	fseek(fp, 0, SEEK_SET);

	BYTE* pe = (BYTE*)malloc(size);
	if (!fread(pe, 1, size, fp)) {
		error("Failed to read PE into memory");
	}

	infos.pe = pe;
	infos.size = size;

	infos.dosHeader = (PIMAGE_DOS_HEADER)pe;
	if (infos.dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		error("Invalid DOS header");
	}

	infos.ntHeader = (PIMAGE_NT_HEADERS64)(pe + infos.dosHeader->e_lfanew);
	if (infos.ntHeader->Signature != IMAGE_NT_SIGNATURE) {
		error("Invalid NT header");
	}

	// Check for 64-bit (PE32+)
	if (infos.ntHeader->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
		error("Not a 64-bit PE file");
	}

	infos.sectionHeader = IMAGE_FIRST_SECTION(infos.ntHeader);

	fclose(fp);
	return infos;
}

int peinjector_main(int argc, char* argv[])
{

	DWORD PID = -1;
	DWORD TID = -1;
	char* path = NULL;
	char* target = NULL;
	int technique = -1;
	int count = 0;


	for (int i = 0; i < argc; i++)
	{
		if (strcmp(argv[i], "-pid") == 0 && i + 1 < argc)
		{
			PID = atoi(argv[++i]);

		}
		if (strcmp(argv[i], "-tid") == 0 && i + 1 < argc)
		{
			TID = atoi(argv[++i]);
		}
		if (strcmp(argv[i], "-sc") == 0 && i + 1 < argc)
		{
			path = argv[++i];
		}
		if (strcmp(argv[i], "-t") == 0 && i + 1 < argc)
		{
			technique = atoi(argv[++i]);
		}
		if (strcmp(argv[i], "-p") == 0 && i + 1 < argc)
		{
			target = argv[++i];
		}
	}
	if (PID == 0)
	{
		PID = GetCurrentProcessId();
	}
	peinfos infos = ReadPeFile(path);

	switch (technique)
	{

	case 0:
		if (path == NULL || target == NULL)
		{
			error("Invalid Syntax | Run With --help for help menu");
			return -1;
		}
		ProcessHollowing(infos, target);
		break;
	default:
		error("Invalid Technique id refer to the help menu for available techniques");
		break;
	}


}