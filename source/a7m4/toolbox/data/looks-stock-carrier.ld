ENTRY(carrier_entry)
diagnostic = 0x35e62c8;
SECTIONS { .carrier 0x35e6244 : { *(.carrier) } /DISCARD/ : { *(.comment*) *(.note*) *(.eh_frame*) } }
