Allows assembling / disassembling x86_64 instructions/opcodes, and emulating with a custom context (which will be dumped).

Uses unicorn, capstone and keystone engines. Works on Windows (not tested on linux, but should work too).

Example:


```
python ASMDeCode.py -e -d -a -c "mov eax, 0x1; mov ebx, 0xC0000002 ; add eax, [ebx] ; mov ebx, 0xD0000 ; mov dword ptr ds:[ebx], 0x12341234" --mem1A 0xC0000000 --mem1V 000001010101DEADBEEFDEAD --mem2A 0xD0000 --mem2V 00000000
[+] Assembly:
b801000000bb020000c00303bb00000d00c70334123412
[+] Disassembly:
        0x1000: mov     eax, 1
        0x1005: mov     ebx, 0xc0000002
        0x100a: add     eax, dword ptr [ebx]
        0x100c: mov     ebx, 0xd0000
        0x1011: mov     dword ptr [ebx], 0x12341234
[+] Emulation:
        [-] Mapping code at 0x10000
        [-] Mapping data at 0xd0000
        [-] Mapping data at 0xc0000000
        [-] Emulation
        [-] Emulation finished
        [-] Context:
                EAX: 1010102 ; EBX: d0000 ; ECX: 0 ; EDX: 0
                ESI: 0 ; EDI: 0 ; EBP: 0 ; ESP: 0
        [-] Memory areas (if any):
                MEMORY1 AT 0xc0000000
                        Not modified
                MEMORY1 AT 0xd0000
34123412
```
