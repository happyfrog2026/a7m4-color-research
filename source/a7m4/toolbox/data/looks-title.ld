ENTRY(title_entry)
native_resume = 0x1c069c0;
SECTIONS
{
  .hook 0x1c069bc : { KEEP(*(.hook)) }
  .title 0x35e6294 : { KEEP(*(.title)) }
  /DISCARD/ : { *(.comment) *(.note*) *(.eh_frame*) }
}
ASSERT(SIZEOF(.hook) == 4, "Only original MOV instruction may be hooked")
ASSERT(SIZEOF(.title) == 40, "Four-slot helper must use exactly 40 bytes")
ASSERT(ADDR(.title) + SIZEOF(.title) <= 0x35e62c8, "Preserve native diagnostic entry")
