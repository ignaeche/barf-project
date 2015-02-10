global _start

_start:
    add esp, 4

    ; mov dword [esp], 0xa

    mov ebx, [esp]
    mov eax, 0x0

    add eax, ebx
