// MIT; original M4 metadata bridge and A7M4 Toolbox contributors.
// New Custom1 route is offline-only and has not been accepted on a camera.
.syntax unified
.thumb
.arch armv7-a

.section .b020_hook,"ax",%progbits
.thumb_func
b020_hook:
    b.w metadata_b020

.section .b029_hook,"ax",%progbits
.thumb_func
b029_hook:
    b.w metadata_b029

.section .sr2_hook,"ax",%progbits
.thumb_func
sr2_hook:
    b.w metadata_sr2

.section .metadata,"ax",%progbits
.global metadata_start, metadata_b020, metadata_sr2, metadata_b029
.global po_name, m9_name, metadata_end
.thumb_func
metadata_start:
metadata_b020:
    // R0 is the original 16-byte output address. R2 is the saved color marker.
    // Only R1 is scratch here: native code overwrote it at this exact hook.
    subw r1, r2, #249
    cmp r1, #3
    bhi 1f
    // Only slots1/4 use M9; slots2/3 keep their existing po metadata.
    adds r1, #1
    tst r1, #2
    ite eq
    adreq.w r1, m9_name
    adrne.w r1, po_name
    b.w b020_copy
1:
    subs r1, r2, #1
    cmp r1, #19
    b.w b020_resume

.thumb_func
metadata_sr2:
    subw r1, r2, #249
    cmp r1, #3
    bhi 2f
    // Only slots1/4 use M9; slots2/3 keep their existing po metadata.
    adds r1, #1
    tst r1, #2
    ite eq
    adreq.w r1, m9_name
    adrne.w r1, po_name
    b.w sr2_copy
2:
    subs r1, r2, #1
    cmp r1, #26
    b.w sr2_resume

.thumb_func
metadata_b029:
    // Keep the true slot marker rather than collapsing the three po labels.
    subw r1, r0, #249
    cmp r1, #3
    bhi 3f
    mov r2, r0
    b.w b029_write
3:
    adds r0, #1
    uxtb r1, r0
    b.w b029_resume

.balign 4
po_name:
    .asciz "po"
    .zero 13
m9_name:
    .asciz "m9"
    .zero 13
metadata_end:
