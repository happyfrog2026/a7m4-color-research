/* M4 6.02/R046-specific, OFFLINE candidate. C2 photobasis integer contract.
 * No AP/CP globals or factory Backup units are changed at runtime.
 */
.syntax unified
.arch armv7-a
.arch_extension idiv
.thumb
.equ parameters, 0x1045d40
.equ gamma_table, 0x1045680

.section .gamma_final_hook,"ax",%progbits
    bl gamma_final
.section .gamma_call_a,"ax",%progbits
    bl gamma_wrapper
.section .gamma_call_b,"ax",%progbits
    bl gamma_wrapper
.section .gamma_record_hook,"ax",%progbits
    bl record_hook
.section .gamma_record_fallback,"ax",%progbits
    b.w fallback_record_hook /* LR is live native data here: never BL */
.section .matrix_call,"ax",%progbits
    bl matrix_wrapper
.section .primary_hook,"ax",%progbits
    b.w primary_wrapper
.section .secondary_hook,"ax",%progbits
    b.w secondary_wrapper

.section .native17,"ax",%progbits
.balign 4
.global native17_start
native17_start:
.type gamma_final,%function
.thumb_func
gamma_final:
    push {r0,r1}        /* retain native return/scratch values at epilogue */
    strb.w r0,[r4,#0x41] /* displaced M4 instruction, before using scratch */
    ldr r0,[r6,#0x10]   /* original marker, unchanged by old ST bridge */
    sub.w r0,r0,#249
    cmp r0,#3
    bhi 3f
    lsls r0,r0,#1
    adds r0,#51
    /* All native mode overrides and validation have already run. Only the
     * two native ST rows are virtualized; other native modes stay native. */
    .irp offset,0x2c,0x30,0x3c
    ldr r1,[r4,#\offset]
    cmp r1,#0
    beq 1f
    cmp r1,#10
    bne 2f
    adds r1,r0,#1
    b 4f
1:  mov r1,r0
4:  str r1,[r4,#\offset]
2:
    .endr
3:  pop {r0,r1}
    bx lr
.size gamma_final,.-gamma_final

.balign 4
.type gamma_wrapper,%function
.thumb_func
gamma_wrapper:
    ldr ip,[r1,#0x2c]
    sub.w ip,ip,#51
    cmp ip,#7
    bhi native_gamma
    push {r4,r5,r6,r7,r8,r9,r10,r11,lr}
    sub sp,#4                 /* 40 saved bytes; preserve AAPCS 8 alignment */
    mov r4,r0                 /* native kind */
    mov r5,r1                 /* native gamma settings */
    mov r6,r2                 /* native output */
    lsr.w r7,ip,#1            /* per-look index */
    sub.w sp,sp,#576           /* one invocation-owned native record */
    mov r8,sp
    ldr r0,[r5,#0x2c]
    movs r1,#28
    mul r0,r1,r0
    movw r1,#(gamma_table & 0xffff)
    movt r1,#(gamma_table >> 16)
    add r0,r1
    ldrb r1,[r5,#0x34]
    ldr.w r1,[r0,r1,lsl #2]
    cmp r1,#0
    beq gamma_no_record       /* M4 still row10 columns0..5 are native NULL */
    mov r0,sp
    movs r2,#144
5:  ldr r3,[r1],#4
    str r3,[r0],#4
    subs r2,#1
    bne 5b
    movw r0,#(parameters & 0xffff)
    movt r0,#(parameters >> 16)
    movs r1,#108
    mla r0,r7,r1,r0
    ldrsh.w r9,[r0]
    ldrsh.w r10,[r0,#2]
    ldrsh.w r11,[r0,#4]
    mov r7,sp
    mov.w ip,#129
6:  ldr r0,[r7]
    ldr r1,[sp,#0x200]
    lsl.w r2,r0,#12
    udiv r1,r2,r1
    rsb.w r2,r1,#4096
    mul r3,r0,r9
    asrs r3,#10
    add.w lr,r0,r3
    mul r3,r0,r10
    asrs r3,#10
    muls r3,r2,r3
    asrs r3,#12
    muls r3,r2,r3
    asrs r3,#12
    add lr,r3
    mul r3,r0,r11
    asrs r3,#10
    muls r3,r1,r3
    asrs r3,#12
    muls r3,r2,r3
    asrs r3,#12
    add lr,r3
    cmp.w lr,#0
    bge 7f
    mov.w lr,#0
7:  movw r3,#65535
    movt r3,#3
    cmp lr,r3
    bls 8f
    mov lr,r3
8:  str lr,[r7],#4
    subs.w ip,ip,#1
    bne 6b
    ldr r0,[sp,#0x200]
    str r0,[sp,#0x220]
    mov r0,r4
    mov r1,r5
    mov r2,r6
    /* Native prologue saves r8 before any use; the guarded record hook reads
     * that saved incoming value, not native's later live r8. */
    bl native_gamma
.global gamma_call_return
gamma_call_return:
    add.w sp,sp,#576
    add sp,#4
    pop {r4,r5,r6,r7,r8,r9,r10,r11,pc}
gamma_no_record:
    mov r0,r4
    mov r1,r5
    mov r2,r6
    add.w sp,sp,#576
    add sp,#4
    pop {r4,r5,r6,r7,r8,r9,r10,r11,lr}
    b.w native_gamma
.size gamma_wrapper,.-gamma_wrapper

.balign 4
.type record_hook,%function
.thumb_func
record_hook:
    /* Actual M4 frame: 20 +16 +108 =144. Incoming LR at+140, r8 at+108. */
    ldr r3,[sp,#140]
    movw ip, #:lower16:(gamma_call_return+1)
    movt ip, #:upper16:(gamma_call_return+1)
    cmp r3,ip
    bne 9f
    ldr r1,[sp,#108]
    bx lr
9:  ldr.w r1,[r1,r2,lsl #2] /* exact original destination/base/index */
    bx lr
.size record_hook,.-record_hook

.balign 4
.type fallback_record_hook,%function
.thumb_func
fallback_record_hook:
    /* Preserve native r1/r2/r3/r4/ip AND live LR. This is a B hook, so no
     * original live LR is lost. 24 saved bytes keep SP eight-aligned.
     * Incoming native frame LR/R8 remain at oldSP+140/+108 respectively. */
    push {r1,r2,r3,r4,ip,lr}
    ldr r3,[sp,#164]
    movw ip, #:lower16:(gamma_call_return+1)
    movt ip, #:upper16:(gamma_call_return+1)
    cmp r3,ip
    bne 12f
    ldr r0,[sp,#132]
    b 13f
12: ldr.w r0,[r0,r6,lsl #2]
13: pop {r1,r2,r3,r4,ip,lr}
    /* Native 3D0E04 LDR/STR then ADDS/CMP overwrite flags before use. */
    b.w gamma_fallback_resume
.size fallback_record_hook,.-fallback_record_hook

.macro post_wrapper name,context,parameter,native,offset,count
.balign 4
.type \name,%function
.thumb_func
\name:
    .ifc \name,secondary_wrapper
    cmp r2,#2
    bhs \native        /* original mode>=2 returns without output writes */
    .endif
    /* M4 native ST photo=0/movie=21. r1 is a matrix sub-selector only in
     * matrix; its color selector is r3. Preserve every original argument. */
    cmp \parameter,#0
    beq 10f
    cmp \parameter,#21
    bne \native
10: cmp \context,#0
    beq \native
    ldr ip,[\context]
    cmp.w ip,#0
    beq \native
    ldrb.w ip,[ip,#1]
    cmp.w ip,#1
    bhi \native
    ldr ip,[\context]
    ldrb.w ip,[ip,#0x2e]
    sub.w ip,ip,#249
    cmp.w ip,#3
    bhi \native
    push {r4,r5,r6,lr}
    mov r4,r0
    mov r5,ip
    bl \native
    movw r6,#(parameters & 0xffff)
    movt r6,#(parameters >> 16)
    movs r0,#108
    mla r6,r5,r0,r6
    adds r6,#\offset
    movs r3,#\count
11: ldrh r0,[r4]
    ldrsh r1,[r6],#2
    add r0,r1
    strh r0,[r4],#2
    subs r3,#1
    bne 11b
    pop {r4,r5,r6,pc}
.size \name,.-\name
.endm
post_wrapper matrix_wrapper,r2,r3,native_matrix,6,27
post_wrapper primary_wrapper,r2,r1,primary_trampoline,60,24
post_wrapper secondary_wrapper,r3,r1,secondary_trampoline,60,8

.balign 4
.type primary_trampoline,%function
.thumb_func
primary_trampoline:
    push {r4,r5,r6,r7,lr}
    add r7,sp,#12
    b.w primary_resume
.type secondary_trampoline,%function
.thumb_func
secondary_trampoline:
    push {r4,r5,r6,r7,lr}
    add r7,sp,#12
    b.w secondary_resume
.global native17_end
native17_end:
