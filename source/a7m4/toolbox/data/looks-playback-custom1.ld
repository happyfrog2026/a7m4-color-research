ENTRY(playback_hook)
playback_native_icon = 0x2434f18;
playback_native_range = 0x2434ee8;
SECTIONS {
 . = 0x2434ee4;
 .hook : { KEEP(*(.hook)) }
 . = 0x50bba60;
 .playback : { KEEP(*(.playback)) }
 /DISCARD/ : { *(.comment) *(.note*) *(.eh_frame*) }
}
