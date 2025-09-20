#include <stdio.h>
#include <Windows.h>
#include "macros.h"
#include "techniques.h"





int main(int argc,char* argv[])
{
	if (argc < 2)
	{
		error("You Must Choose A mode");
	}
	if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0)
	{
		printf("RavenInjector - Cute Process Injector :3\n");
		printf("\033[1;35m" 

			"       __                                                     __  \n"
			 "     /  | /  |                     /       |           /    /  | \n"
			 "    (___|(___|      ___  ___      (  ___     ___  ___ (___ (   | ___ \n"
			 "    |\\       ) \\  )|___)|   )     | |   )  )|___)|    |    |   )|   ) \n"
			 "    | \\     /   \\/ |__  |  /      | |  /  / |__  |__  |__  |__/ |  \n"
			 "                                       __/ \n"
			"\n"
			"\033[1;36m"
			"               [ R4ven Inject0r ]\n"

			"\033[1;31m"
			"     [!] For Research & Educational Use Only\n"
			"\033[0m\n");
		printf("----------------------------------------\n");
		printf("-s           Shellcode Injection\n\n");
		printf("Options:\n\n");
		printf("-pid        the target process id (0 for current process)\n");
		printf("-tid        the target thread id (0 for main thread)\n");
		printf("-sc         the shellcode path \n");
		printf("-t          injection technique (-l to list available techniques)\n\n");
		printf("  EXAMPLE : ./raveninjector.exe -s -pid <PID> -tid <TID> -sc <SHELLCODE> -t <TECH_ID>\n\n");
		printf("----------------------------------------\n");
		printf("-dll          Dll Injection\n\n");
		printf("Options:\n\n");
		printf("-pid        the target process id (0 for current process)\n");
		printf("-tid        the target thread id (0 for main thread)\n");
		printf("-sc         the Dll path \n");
		printf("-t          injection technique (-l to list available techniques)\n\n");
		printf("-v          the target process path\n");

		printf("  EXAMPLE : ./raveninjector.exe -pe -pid <PID> -tid <TID> -sc <PE.exe> -t <TECH_ID>\n\n");
		printf("-h           shows this help menu\n\n");
		printf("----------------------------------------\n");
		printf("To List Availabe Techniques add -l after choosing a payload\n");
		printf("  EXAMPLE : ./raveninjector.exe -pe -l --------------------------- to list available pe injection techniques\n\n");
		printf("----------------------------------------\n");
		printf("-e          Encryptor\n\n");
		printf("Options:\n\n");
		printf("-a        Encryption Algorithm (-l for available algorithms)\n");

		printf("----------------------------------------\n");
		printf("Stealth Techniques\n");
		printf("-w         Wait X seconds (if not added the default value is used (3 seconds) --------- coming in the next update\n"); 
		printf("-d         must be specified in case the payload is encrypted (run the program with -e -l to list available decryption algorithms)\n");

		return 0;

	}
		if (strcmp(argv[1], "-s") == 0)
		{

			if (argc >= 3 && strcmp(argv[2], "-l") == 0)
			{

					printf("Available Shellcode Injection Techniques :\n\n");

					printf("----> 0\t- Shellcode Process Injection\n\n");
					printf("Requirements :\n\n");
					printf("-pid\tProcess Id (0 for current process)\n");
					printf("-sc\tshellcode path \n\n");

					printf("----> 1\t- Thread Hijacking Process Injection\n\n");
					printf("Requirements :\n\n");
					printf("-pid\tProcess Id (0 for current process)\n");
					printf("-tid\tthread Id (0 for main thread)\n");
					printf("-sc\tshellcode path \n\n");

					printf("----> 2\t- QueueUserAPC Injection\n\n");
					printf("Requirements :\n\n");
					printf("-pid\tProcess Id (0 for current process)\n");
					printf("-tid\tthread Id (0 for main thread)\n");
					printf("-sc\tshellcode path \n\n");

					printf("----> 3\t- EarlyBird APCInjection\n\n");
					printf("Requirements :\n\n");
					printf("-sc\tshellcode path \n\n");

					
					printf("----> 4\t- MapViewOfSectionInjection\n\n");
					printf("Requirements :\n\n");
					printf("-pid\tProcess Id (0 for current process)\n");
					printf("-sc\tshellcode path \n\n");
					return 0;

			}

			shellcodeinjection_main(argc - 2, &argv[2]);
			return 0;
		}

		else if (strcmp(argv[1], "-dll") == 0)
		{
			if (argc >= 3 && strcmp(argv[2], "-l") == 0)
			{
				printf("Available Pe Injection Techniques :\n\n");

				printf("----> 0\t- Manual Mapping Dll Injection\n\n");
				printf("Requirements :\n\n");
				printf("-pid\tProcess Id (0 for current process)\n");
				printf("-sc\tPe path \n\n");

				printf("----> 1\t- Process Hollowing\n\n");
				printf("Requirements :\n\n");
				printf("-pid\tProcess Id (0 for current process)\n");
				printf("-sc\tPe path \n\n");
				printf("-v\tThe Target Process that will be hollowed \n\n");

				printf("----> 1\t- Normal Dll Injection Via LoadLibraryA\n\n");
				printf("Requirements :\n\n");
				printf("-pid\tProcess Id (0 for current process)\n");
				printf("-sc\tdll path \n\n");

				printf("----> 1\t- LdrLoadDll Injection\n\n");
				printf("Requirements :\n\n");
				printf("-pid\tProcess Id (0 for current process)\n");
				printf("-sc\tDll path \n\n");
				return 0;
			}
			
			Peinjector_main(argc - 2, &argv[2]);
		}
		
		else if (strcmp(argv[1], "-e") == 0)
		{
			if (argc >= 3 && strcmp(argv[2], "-l") == 0)
			{
				printf("Available Encryption Algorithms :\n\n");

				printf("----> 0\t- Xor Encryption\n\n");
				printf("Requirements :\n\n");
				printf("-sc\tShellcode path\n\n");

				printf("Options :\n\n");
				printf("-key\tuse a specific key for encryption\n");
				return 0;
			}
			encryptor_main(argc - 2, &argv[2]);
		}
		else { error("Invalid Mode Please run the program with -h for the help menu"); }
}