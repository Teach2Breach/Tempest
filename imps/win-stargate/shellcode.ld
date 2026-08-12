/*
 * BM-PA1001-style PIC linker script — single PE `.text` (code + rodata + data + bss; idata discarded).
 * `__data_start__` marks the writable tail inside the merged section (maps / debugging).
 * VMA preamble + `.rdata$.refptr*` ordering satisfy mingw REL32 from code to refptr slots.
 */
OUTPUT_FORMAT(pei-x86-64)
SECTIONS
{
  . = SIZEOF_HEADERS;
  . = ALIGN(__section_alignment__);
  .text 0x140000000 + (__section_alignment__ < 0x1000 ? . : __section_alignment__) :
  {
    __pic_image_start = .;
    *(.text$A)
    *(.text)
    *(.text.*)
    /* Refptr slots must sit next to code so IMAGE_REL_AMD64_REL32 can reach (mingw). */
    *(.rdata$.refptr*)
    *(.rdata)
    *(.rdata.*)
    __data_start__ = .;
    *(.data)
    *(.data.*)
    *(.bss)
    *(.bss.*)
    __pic_image_end = .;
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
