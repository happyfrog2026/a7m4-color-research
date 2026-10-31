// MIT; A7M4 Toolbox contributors. New offline-only stock Custom1 route.
// Other markers retain the native range/invalid behavior: no absent IDs used.
.section .hook,"ax",@progbits
.global playback_hook
playback_hook:
    b playback_entry
.section .playback,"ax",@progbits
.global playback_entry
playback_entry:
    cmp w1, #249
    b.ne legacy
    mov w0, #0x1e9a
    b playback_native_icon
legacy:
    cmp w1, #23
    b playback_native_range
