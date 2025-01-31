section .data
    msg db "Hello World", 0

section .text
global _start
_start:
    DQXZ    ; LOAD msg address
    GHTL    ; PUSH msg to stack
    PNAF    ; CALL print function
    NMPQ    ; POP result
    
    LUJK    ; MOV exit code to register
    GHTL    ; PUSH 0 (exit code)
    QJMC    ; HLT/exit program
