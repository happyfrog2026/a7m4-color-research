// MIT; A7M4 Toolbox contributors, original M4 carrier adaptation.
// Only Custom1/ST emits249. Other custom positions retain native base behavior.
.section .carrier,"ax",@progbits
.global carrier_entry
carrier_entry:
    cmp w0, #16
    b.eq special
    cbnz w1, legacy
    cmp w0, #10
    b.ne legacy
    mov w0, #249
    b store
legacy:
    cmp w1, #11
    b.hi diagnostic
    adr x0, native_map
    ldrb w0, [x0, w1, uxtw]
store:
    strb w0, [x2]
    ret
special:
    mov w0, #-1
    b store
native_map:
    .byte 0,3,2,1,16,15,17,18,5,13,19,20
    .balign 4
    .org 80
