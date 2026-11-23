// MIT; A7M4 Toolbox contributors. Adapted from the original M4 playback bridge.
// New offline-only Custom1 route: no physical camera acceptance is claimed.
.section .hook,"ax",@progbits
.global playback_hook
playback_hook:
    b playback_entry

.section .playback,"ax",@progbits
.global playback_entry
playback_entry:
    // Preserve W1, SP, LR and all callee-saved registers. Only W0/flags change.
    sub w0, w1, #249
    cmp w0, #3
    b.hi legacy
    mov w0, #0x1e98
    cinc w0, w0, eq             // Custom4 remains 1e99.
    cmp w1, #249
    cinc w0, w0, eq
    cinc w0, w0, eq             // Custom1 gets independent 1e9a.
    b playback_native_icon
legacy:
    cmp w1, #23
    b playback_native_range
