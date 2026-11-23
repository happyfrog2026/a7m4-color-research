ENTRY(native17_start)
SECTIONS {
 .gamma_record_hook 0x3d0726 : { *(.gamma_record_hook) }
 .gamma_record_fallback 0x3d0e00 : { *(.gamma_record_fallback) }
 .gamma_call_a 0x3d0ed6 : { *(.gamma_call_a) }
 .matrix_call 0x6a3efe : { *(.matrix_call) }
 .primary_hook 0x6a4e76 : { *(.primary_hook) }
 .secondary_hook 0x6a51ce : { *(.secondary_hook) }
 .gamma_call_b 0x9d0f14 : { *(.gamma_call_b) }
 .gamma_final_hook 0x9d12cc : { *(.gamma_final_hook) }
 .native17 0xba6380 : { *(.native17) }
 ASSERT(. <= 0xba66e0,"native17 exceeds independently proposed864B RX allocation")
 /DISCARD/ : { *(.ARM.exidx*) *(.comment*) *(.note*) }
}
native_gamma = 0x3d06fd;
native_matrix = 0x6a4c25;
primary_resume = 0x6a4e7b;
secondary_resume = 0x6a51d3;
gamma_fallback_resume = 0x3d0e05;
