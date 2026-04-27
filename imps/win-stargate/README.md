# win-stargate (Windows C implant)

Self-contained Stargate-based beacon: **`stargate/`** (vendored T2005 C/asm), **`src/`** (beacon + entries + PIC glue), and **`exports_beacon.def`** for the DLL.

## Build (Linux, MinGW)

```bash
make            # beacon.exe
make dll        # beacon.dll
make raw        # beacon.bin (flat image, no PE)
make all        # exe + dll + raw + runner
make runner     # tools/shellcode_runner.exe
```

Requires `x86_64-w64-mingw32-gcc` and `make` on `PATH`.

## Test shellcode on a Windows lab machine

The flat `beacon.bin` is **`.rdata` + `.text` + `.data`** bytes in that order. The CPU entry (`shellcode_entry`) is **not** at file offset 0 — it lines up with the start of **`.text`** after the **`.rdata`** prefix. The build writes **`beacon.bin.entry_offset`** (one line, hex) so the harness knows where to jump.

1. Build `make raw` (or copy artifacts from a build host).
2. Copy **`tools/shellcode_runner.exe`**, **`beacon.bin`**, and **`beacon.bin.entry_offset`** to the lab machine (same folder).
3. Run:

```text
tools\shellcode_runner.exe beacon.bin
```

Optional arguments: **`entry_offset`** (hex) if you have no sidecar file, then **`alloc_base`** (hex) if you want to try mapping at a specific virtual address (e.g. the PE default `0x0000014000000000`). **Load address** only matters if the compiled blob still contains **absolute** references to a fixed image base; a fully PIC blob works at any `VirtualAlloc` address — if it crashes at `NULL` hint but works with a specific base, you have a base-relocation issue to fix in the link step.

The runner prints whether execution **returned**; many implants never return to the caller.

## Threading and parity (vs. `windows_noldr`)

The C beacon is **single-threaded** for the C2 loop and task execution so far. The legacy Rust implant (`imps/windows_noldr`, `proto.rs`) already had a **second thread** for **SOCKS** (`mpsc` + `thread::spawn`) plus many tasks: `whoami`, `ipconfig`, `ps`, shell fs (`cd`/`pwd`/`ls`/`catfile`), `getfile`/`sendfile`, `cmd`/`pwsh`, `wmi`, `bof`, `inject`, `runpe`, `socks`, live `sleep`, `kill`. When you add those here, expect to **spawn worker threads** for anything that blocks (SOCKS, long jobs) and keep the **main thread** on the HTTP poll, or use explicit queuing. **Do not** share `g_c2coll` / Morpheus context across threads without synchronization.
