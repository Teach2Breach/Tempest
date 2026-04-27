/*
 * Monolithic shellcode: merge sections, discard PE import tables & metadata.
 * After link: objcopy -O binary -j .text → raw opcode blob (no MZ).
 * Adapted from techniques/BM-PA1001/code/c/pic.ld
 */
SECTIONS {
    .text : {
        *(.text$A)
        *(.text)
        *(.text.*)
        *(.rdata)
        *(.rdata.*)
        *(.data)
        *(.data.*)
        *(.bss)
        *(.bss.*)
    }
    /DISCARD/ : {
        *(.comment)
        *(.drectve)
        *(.pdata)
        *(.xdata)
        *(.reloc)
        *(.eh_frame)
        *(.eh_frame_hdr)
        *(.ctors)
        *(.dtors)
        *(.CRT*)
        *(.tls)
        *(.debug*)
        *(.idata*)
    }
}
