#include <stdio.h>
#include <Windows.h>
#include "macros.h"
#include "techniques.h"





int main(int argc,char* argv[])
{
	if (argc < 2)
	{
		error("You Must Choose A mode");
		return -1;
	}
	
		if (strcmp(argv[1], "-s") == 0)
		{

			if (argc >= 4 && strcmp(argv[2], "-l") == 0 && strcmp(argv[3], "-t") == 0)
			{

					printf("Available Shellcode Injection Techniques :\n\n");

					printf("---- 0\t- Shellcode Process Injection\n\n");
					printf("Requirements :\n\n");
					printf("-pid\tProcess Id (0 for current process)\n");
					printf("-sc\tshellcode path (use double backslashes)\n");

					printf("---- 1\t- Thread Hijacking Process Injection\n\n");
					printf("Requirements :\n\n");
					printf("-pid\tProcess Id (0 for current process)\n");
					printf("-tid\tthread Id (0 for main thread)\n");
					printf("-sc\tshellcode path (use double backslashes)\n");

					printf("---- 2\t- QueueUserAPC Injection\n\n");
					printf("Requirements :\n\n");
					printf("-pid\tProcess Id (0 for current process)\n");
					printf("-tid\tthread Id (0 for main thread)\n");
					printf("-sc\tshellcode path (use double backslashes)\n");

					printf("---- 3\t- EarlyBird APCInjection\n\n");
					printf("Requirements :\n\n");
					printf("-sc\tshellcode path (use double backslashes)\n");


					return 0;

			}

			shellcodeinjection_main(argc - 2, &argv[2]);
			return 0;
		}
		if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0)
		{
			printf("RavenInjector - Modular Shellcode / PE Loader\n");
			printf("----------------------------------------\n");
			printf("-s           Shellcode Injection\n\n");
			printf("Options:\n\n");
			printf("-pid        the target process id (0 for current process)\n");
			printf("-tid        the target thread id (0 for main thread)\n");
			printf("-sc         the shellcode path (use double back slashes)\n");
			printf("-t          injection technique (-l to list available techniques)\n\n");
			printf("  EXAMPLE : ./raveninjector.exe -s -pid <PID> -tid <TID> -sc <SHELLCODE> -t <TECH_ID>\n\n");
			printf("-pe          Pe Loading -----------> coming soon");
		}
		if (strcmp(argv[1], "-pe") == 0)
		{
			peinjector_main(argc - 2, &argv[2]);
		}



}