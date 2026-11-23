ENTRY(metadata_start)
SECTIONS {
 .b020_hook 0x23485a : { *(.b020_hook) }
 .b029_hook 0x2348f4 : { *(.b029_hook) }
 .sr2_hook 0x235834 : { *(.sr2_hook) }
 .metadata 0xba6650 : { *(.metadata) }
 ASSERT(. <= 0xba66e0,"metadata exceeds native17 owned 144-byte tail")
 /DISCARD/ : { *(.ARM.exidx*) *(.comment*) *(.note*) }
}
b020_resume = 0x23485f;
b020_copy = 0x2348e9;
b029_resume = 0x2348f9;
b029_write = 0x23490f;
sr2_resume = 0x235839;
sr2_copy = 0x2358a5;
