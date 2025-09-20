#pragma once

#define okay(msg , ...) printf("[+] "msg"\n",##__VA_ARGS__)
#define error(msg) do { printf("[-] %s\n", msg); exit(EXIT_FAILURE); } while(0)
#define warn(msg , ...) printf("[!] "msg"\n",##__VA_ARGS__)
#define input(msg , ...) printf("[->] "msg" > ",##__VA_ARGS__)

#define ViewUnmap 2
#define ViewShare 1

#define PROCESS_HOLLOWING 0
#define MANUAL_MAPPING_DLL_INJECTION 1
#define NORMAL_DLL_INJECTION 2
#define LDR_LOADDLL_INJECTION 3



#define PROCESS_INJECTION 0
#define THREAD_HIJACKING 1
#define QUEUE_USER_APC_INJECTION 2 
#define EARLY_BIRD 3
#define MAP_VIEW_OF_SECTION_INJECTION 4


