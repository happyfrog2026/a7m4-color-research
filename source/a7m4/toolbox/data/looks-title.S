// Offline M4 6.02 four-slot labels. No converter/runtime/settings changes.
// Native getter entry STP remains at 0x1c069b8; replace only MOV x29,sp.
// Same approach as C2 standalone title hook, with M4 item IDs/addresses.
.section .title,"ax",@progbits
.p2align 2
.global title_entry
title_entry:
    mov x29, sp
    sub w2, w1, #0x858
    cmp w2, #3
    b.hi native_resume_bridge
    mov w0, #0xabe2
    movk w0, #0x200, lsl #16
    add w0, w0, w2
    ldp x29, x30, [sp], #16
    ret
native_resume_bridge:
    b native_resume

.section .hook,"ax",@progbits
.p2align 2
.global title_hook
title_hook:
    b title_entry
