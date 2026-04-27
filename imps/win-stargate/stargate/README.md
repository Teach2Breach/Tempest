# Stargate + BM-T2005 (vendored)

This directory is the **entire** C/asm source for Stargate, Moonwalk, bm_spoof, and syscall stubs used by the win-stargate implant. It is **vendored and maintained in-repo** so production builds of the C2 framework do not depend on `techniques/…` (that tree may be omitted from a minimal clone).

A parallel copy may still exist under `techniques/BM-T2005/code/c` for development reference; **the Makefile only includes headers and sources from this folder.**

Edits for Tempest (e.g. `TEMPEST_PIC_SHELLCODE` paths in `moonwalk.c`, `bm_spoof.c`, `stargate.c`) are applied here.
