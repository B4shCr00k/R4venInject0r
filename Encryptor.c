#include "Techniques.h"
#include "macros.h"
#include "structs.h"

/*void generate_random_key(BYTE* key, size_t key_len) {
	srand((unsigned int)time(NULL));
	for (int i = 0; i < key_len; i++) {
		key[i] = rand() % 256;
	}
}
*/
/*int XorEncryption(shellcodeinfos infos, int option)
{
	BYTE key[10] = NULL;
	generate_random_key(key, 10);

	for (int i = 0; i < infos.size; i++)
	{
		infos.shellcode[i] = infos.shellcode[i] ^ key[i % 10];
	}
}*/