# Manual Windows lab test (win-stargate)

Use this when you want to validate a build outside CI — e.g. after changing `imps/win-stargate/` or Anvil `build_imp`.

Automated coverage (run these first):

| Layer | What runs | Where |
|-------|-----------|--------|
| Wire protocol | Encrypted `POST /js`, `/index`, operator auth | `cargo test` in `Anvil/` (Linux) |
| Cross-compile | `make exe` produces `beacon.exe` | Linux CI (`mingw-w64`) |
| Full E2E | Anvil + `build_imp` + running `beacon.exe` | GitHub Actions `windows-smoke.yml` |

## Quick lab run (Windows)

1. **Build Anvil** on the server/lab host (`Anvil/`):
   ```powershell
   cargo build --release
   ```
2. **TLS certs** — set paths in `Anvil/config.toml` under `[cert]` (see `Anvil/README.md`).
3. **Start Anvil** from `Anvil/` (cwd matters for `build_imp` → `../imps/win-stargate`):
   ```powershell
   .\target\release\anvil.exe
   ```
   Note the `encoded AES key:` line in the log (43 chars).
4. **Operator client** — use `conduit_gui` or curl against `conduit_port` (default 8443):
   - `POST /authenticate` with Basic `forge:forge` (change in config)
   - `POST /build_imp` with headers: `X-Target=windows_stargate`, `X-Format=exe`, callback IP/port, sleep, jitter
   - Save response bytes as `beacon.exe`
5. **Run implant** on the target Windows host (same machine or remote):
   ```text
   beacon.exe
   ```
6. **Verify** — `GET /imps` with operator token should list a row with `os` containing `windows`.

## Shellcode (optional)

```bash
# Linux build host
cd imps/win-stargate
export AES_KEY='<43-char key from Anvil log>'
make raw SERVER=192.168.1.10 PORT=443 SLEEP=2 JITTER=0 UUID='<uuid from build_imp>'
```

Copy `beacon.bin`, `beacon.bin.entry_offset`, and `tools/shellcode_runner.exe` to the lab; see `imps/win-stargate/README.md`.

## Troubleshooting

| Symptom | Check |
|---------|--------|
| `build_imp` 500, make errors | Anvil cwd is `Anvil/`; MinGW on PATH; `TEMPEST_WIN_STARGATE_DIR` if layout differs |
| Implant never appears | UUID in beacon must exist in `unique_identifiers` (inserted by `build_imp`); callback IP/port reachable; TLS cert trusted or implant ignores cert errors |
| Wrong crypto | Rebuild implant after new `aes_key.bin`; `AES_KEY` in make must match running Anvil |

## One-command CI equivalent (Windows)

```powershell
.\scripts\windows-beacon-smoke.ps1
```

Uses ephemeral ports 8444/8445 and self-signed certs under `%TEMP%\tempest-smoke`.
