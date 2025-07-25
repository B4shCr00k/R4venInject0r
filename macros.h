#pragma once

#define okay(msg , ...) printf("[+] "msg"\n",##__VA_ARGS__)
#define error(msg , ...) printf("[-] "msg"\n",##__VA_ARGS__)
#define warn(msg , ...) printf("[!] "msg"\n",##__VA_ARGS__)
#define input(msg , ...) printf("[->] "msg" > ",##__VA_ARGS__)

#define ViewUnmap 2
#define ViewShare 1
