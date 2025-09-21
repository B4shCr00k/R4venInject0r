# R4ven Injector :3 

A feature rich Dll/shellcode process injector with many different techniques to expirement with 

i will keep updating with new techniques + maybe add a gui 

<img width="2549" height="1214" alt="Screenshot 2025-09-21 140214" src="https://github.com/user-attachments/assets/d54c5510-dcff-4c1d-94fd-34371ecf252f" />

-----------------------------------------------

## Included Dll Injection Techniques 

- Process Hollowing
- Manual Mapping Dll Injection
- LoadLibraryA Dll Injection (Normal dll injection)
- LdrLoadDll Injection

## Included Dll Injection Techniques
- Basic Shellcode Process Injection
- ThreadHijacking
- QueueUserAPCInjection
- EarlyBird
- MapViewOfSectionInjection

## A simple Encrypter/Decrypter
- Only XOR

### To Add In The Next Version :
- Kernel Injection (main)
- Reflective Dll Injection
- LdrpLoadDll Injection
- SetWindowsHookEx injection
- More Encrypting Algorithms
- KernelCallback
- FakeVEH

-----------------------------------------------
this tool was mainly made for educational purposes il soon add a doc explaining all these techniques i also tried to write the code as simple as i can this is basically documenting what i learned in one project 

## Usage 
Help Message 
```c
PS D:\Projects\raveninjector\x64\Release> .\raveninjector.exe -h
RavenInjector - Cute Process Injector :3
       __                                                     __
     /  | /  |                     /       |           /    /  |
    (___|(___|      ___  ___      (  ___     ___  ___ (___ (   | ___
    |\       ) \  )|___)|   )     | |   )  )|___)|    |    |   )|   )
    | \     /   \/ |__  |  /      | |  /  / |__  |__  |__  |__/ |
                                       __/

               [ R4ven Inject0r ]
     [!] For Research & Educational Use Only

----------------------------------------
-s           Shellcode Injection

Options:

-pid        the target process id (0 for current process)
-tid        the target thread id (0 for main thread)
-sc         the shellcode path
-t          injection technique (-l to list available techniques)

  EXAMPLE : ./raveninjector.exe -s -pid <PID> -tid <TID> -sc <SHELLCODE> -t <TECH_ID>

----------------------------------------
-dll          Dll Injection

Options:

-pid        the target process id (0 for current process)
-tid        the target thread id (0 for main thread)
-sc         the Dll path
-t          injection technique (-l to list available techniques)

-v          the target process path
  EXAMPLE : ./raveninjector.exe -pe -pid <PID> -tid <TID> -sc <PE.exe> -t <TECH_ID>

-h           shows this help menu

----------------------------------------
To List Availabe Techniques add -l after choosing a payload
  EXAMPLE : ./raveninjector.exe -pe -l --------------------------- to list available pe injection techniques

----------------------------------------
-e          Encryptor

Options:

-a        Encryption Algorithm (-l for available algorithms)
----------------------------------------
Stealth Techniques
-w         Wait X seconds (if not added the default value is used (3 seconds) --------- coming in the next update
-d         must be specified in case the payload is encrypted (run the program with -e -l to list available decryption algorithms)
```
dll injection techniques
```
.\raveninjector.exe -dll -l
Available Pe Injection Techniques :

----> 0 - Manual Mapping Dll Injection

Requirements :

-pid    Process Id (0 for current process)
-sc     Pe path

----> 1 - Process Hollowing

Requirements :

-pid    Process Id (0 for current process)
-sc     Pe path

-v      The Target Process that will be hollowed

----> 1 - Normal Dll Injection Via LoadLibraryA

Requirements :

-pid    Process Id (0 for current process)
-sc     dll path

----> 1 - LdrLoadDll Injection

Requirements :

-pid    Process Id (0 for current process)
-sc     Dll path
```
shellcode injection techniques 

```
.\raveninjector.exe -s -l
Available Shellcode Injection Techniques :

----> 0 - Shellcode Process Injection

Requirements :

-pid    Process Id (0 for current process)
-sc     shellcode path

----> 1 - Thread Hijacking Process Injection

Requirements :

-pid    Process Id (0 for current process)
-tid    thread Id (0 for main thread)
-sc     shellcode path

----> 2 - QueueUserAPC Injection

Requirements :

-pid    Process Id (0 for current process)
-tid    thread Id (0 for main thread)
-sc     shellcode path

----> 3 - EarlyBird APCInjection

Requirements :

-sc     shellcode path

----> 4 - MapViewOfSectionInjection

Requirements :

-pid    Process Id (0 for current process)
-sc     shellcode path
```
Encryption (Alpha)
```
 .\raveninjector.exe -e -l
Available Encryption Algorithms :

----> 0 - Xor Encryption

Requirements :

-sc     Shellcode path

Options :

-key    use a specific key for encryption
```

Tested On Windows 11

<img width="902" height="482" alt="image" src="https://github.com/user-attachments/assets/d5f0e7d7-4b48-40f5-8fe3-913a778fc61e" />

should also work fine on windows 10

![cyberpunk2077-keanu](https://github.com/user-attachments/assets/d0d91daf-3e1c-48ce-bdf4-459ae159024e)



