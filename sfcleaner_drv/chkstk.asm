; chkstk.asm — x64 栈探测 (等价 CRT 实现), RAX = 需探测字节数
_TEXT SEGMENT
PUBLIC __chkstk
__chkstk PROC
    sub     rsp, 10h
    mov     [rsp], r10
    mov     [rsp+8], r11
    xor     r11, r11
    lea     r10, [rsp+18h]
    sub     r10, rax
    cmovb   r10, r11
    mov     r11, qword ptr gs:[10h]
    cmp     r10, r11
    jae     short l1
    and     r10w, 0F000h
l2:
    lea     r11, [r11-1000h]
    mov     byte ptr [r11], 0
    cmp     r10, r11
    jne     short l2
l1:
    mov     r10, [rsp]
    mov     r11, [rsp+8]
    add     rsp, 10h
    ret
__chkstk ENDP
_TEXT ENDS
END
