#include "Techniques.h"
#include "macros.h"
#include "structs.h"
#include "Encryption.h"

int Key_Gen()
{
	unsigned char keystream[30];
	char* keyfilename = NULL;
	int length = sizeof(keystream);
	

	srand((unsigned int)time(NULL));
	

	for (int i = 0; i < sizeof(keystream); i++) {
		keystream[i] = (unsigned char)(rand() % 256);
	}
	okay("Output Key file path > ");
	fgets(keyfilename, 20, 0);
	FILE* fp = fopen(keyfilename, "wb");
	if (fp == NULL)
	{
		error("Failed to create Key File");
	}
	fwrite(keystream, 1, length,fp);
	okay("Key Generated (file name : %s)",keyfilename);
	fclose(fp);
	return 0;
}


int xor_file(char* shellcode, char* key)
{
	char* keyname = NULL;
	char* outputfile = NULL;

	FILE* sh_fp = fopen(shellcode, "rb");

	FILE* key_fp = fopen(key, "rb");

	char choice[3];
	if (sh_fp == NULL)
	{
		error("shellcode not found");
	}
	if (key_fp == NULL)
	{
		printf("[-] Key Not found..... Generate a new Key ?\n Y/N\n");
		fgets(choice,sizeof(choice),0);

		
		if (strcmp(choice,"Y") == 0 || strcmp(choice, "y") == 0 || strcmp(choice, "yes") == 0)
		{
			okay("Generating a new key .....");
			okay("key output file name > ");
			fgets(keyname, 50, 0);
			Key_Gen(keyname);
			okay("Key generated (%s)",keyname);
		}
		else {
			error("Key Not found make sure a key.bin exists in the current directory containing the correct key");
		}
	}
	unsigned char keystream[30];
	fread(keystream, 1, 30, key_fp);

	fseek(sh_fp, 0, SEEK_END);
	size_t size = ftell(sh_fp);
	fseek(sh_fp, 0, SEEK_SET);

	BYTE* pSc = (BYTE*)malloc(size);
	fread(pSc, 1, size, sh_fp);
	for (size_t i = 0; i < size; i++)
	{
		pSc[i] ^= keystream[i % 30];
	}
	okay("Enter the output file name and path > ");
	fgets(outputfile, 20, 0);

	FILE* new = fopen(outputfile, "wb");
	fwrite(pSc, 1, size, new);
	okay("File Encrypted (%s)",outputfile);
}

// AES encryption coming soon
int AES_256_file(char* shellcode, char* key)
{
	BCRYPT_ALG_HANDLE hAlg = NULL;
	BCRYPT_KEY_HANDLE hKey = NULL;
	NTSTATUS status;
	DWORD cbData = 0, cbKeyObject = 0, cbBlockLen = 0;
	PBYTE pbKeyObject = NULL;


	status = BCryptOpenAlgorithmProvider(&hAlg,BCRYPT_AES_ALGORITHM,NULL,0);
	if (status != 0)
	{
		error("BCryptOpenAlgorithmProvider failed");
	}
	status = BCryptGetProperty(hAlg,BCRYPT_OBJECT_LENGTH,(PBYTE)&cbKeyObject,sizeof(DWORD),&cbData,0);
	if (status != 0)  error("BCryptGetProperty failed"); 
	

}

int XOR_dec(BYTE* payload, size_t size,char *key)
{
	char choice[3];

	FILE* fp = fopen(key, "rb");
	if (fp == NULL)
	{
		error("Key Not found Please Run the injector with -e to encrypt the shellcode and generate a new key");
	}
	unsigned char keystream[30];
	fread(keystream, 1, sizeof(keystream), fp);
	for (size_t i = 0; i < size; i++)
	{
		payload[i] ^= keystream[i % 30];
	}
}

int encryptor_main(int argc, char* argv[])
{
	int algorithm = -1;
	char* key = NULL;
	char* path = NULL;

	for (int i = 0; i < argc; i++)
	{
		if (strcmp(argv[i], "-sc") == 0 && i + 1 < argc)
		{
			path = argv[++i];
		}
		if (strcmp(argv[i], "-t") == 0 && i + 1 < argc)
		{
			algorithm = atoi(argv[++i]);

		}
		if (strcmp(argv[i], "-key") == 0 && i + 1 < argc)
		{
			key = argv[++i];
		}
	}
	if (key == NULL)
	{
		okay("No Key specified Now generating a new key .....");
		Key_Gen();
	}
	switch (algorithm)
	{
	case XOR:
		xor_file(path,key);
		break;
	}
}

