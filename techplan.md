## Tempest GUI (Dioxus) — Technical Implementation Plan

This document defines a step-by-step plan to build a Rust GUI client that achieves feature parity with the existing `conduit` TUI client, using Dioxus for the UI. Steps are intentionally small and LLM-friendly so we can implement them incrementally and refer back as we go.

### Goals
- Reproduce all `conduit` capabilities in a GUI:
  - Secure auth against Anvil and token handling
  - Live dashboard of imps with status and last check-in
  - Session interaction (issue tasks, view output)
  - Build new implants
  - File operations: sendfile/getfile, bof upload, inject/runpe upload flows
  - SOCKS command issuance
  - Persistent and scrollable output view with continuous polling
  - Config-driven server port (read `conduit/config.toml`), append port to URL if missing

### High-Level Architecture
- Crate: `conduit_gui` at repo root (sibling to `conduit/` and `Anvil/`).
- Tech stack:
  - UI: `dioxus`, `dioxus-desktop` (Wry-based; no need for separate Tauri unless later desired)
  - Async/runtime: `tokio`
  - HTTP: `reqwest` (TLS with `danger_accept_invalid_certs(true)` to match TUI behavior)
  - Data: `serde`, `serde_json`
  - Config: `config` crate to read `conduit/config.toml` for server port
  - Base64: `base64`
  - File dialogs: `rfd` (open/save file picker)
  - State mgmt: Dioxus hooks (`use_signal`/`use_state`, `use_coroutine`, `use_context`) and small service layer

### API Contract (parity with TUI)
- POST `https://{url}/authenticate`
  - Header: `Authorization: Basic <base64(username:password)>`
  - Returns: token string body
- GET `https://{url}/imps`
  - Header: `X-Token: <token>`
  - Returns: JSON `Vec<ImpInfo>`
- POST `https://{url}/issue_task`
  - Headers: `x-token`, `x-session`, `x-task`
  - Returns: 2xx on success
- GET `https://{url}/retrieve_all_out`
  - Header: `x-token`
  - Returns: base64 (URL_SAFE, NO_PAD) encoded concatenated output string
- POST `https://{url}/build_imp`
  - Headers: `x-token`, `x-target`, `x-target-ip`, `x-target-port`, `x-tsleep`, `x-format`, `x-jitter`
  - Returns: binary bytes (write file with appropriate extension as TUI does)
- POST `https://{url}/bofload`
  - Headers: `X-Filename`, `Content-Type: application/octet-stream`, `X-Token`
  - Body: raw binary

### Data Models (mirror TUI)
- `ImpInfo` fields: `session`, `ip`, `username`, `domain`, `os`, `imp_pid`, `process_name`, `sleep`, `last_check_in`.
- Output stream: decoded string lines; save file artifacts under `loot/` as in TUI.

### UI Flow
1. Login Screen
   - Inputs: URL, Username, Password
   - Automatically append port from `conduit/config.toml` if URL lacks port
   - On submit → authenticate → store token → navigate to Dashboard

2. Dashboard Screen
   - Table of imps (scrollable): columns as TUI; session shown as last 8 chars
   - Row color red if last-check-in is older than sleep + 60s (match TUI logic)
   - Buttons/actions:
     - Open Session (select an imp)
     - Build Implant (opens modal/dialog)
     - Refresh (manual)
   - Background task: poll `/imps` every second, update list and connection status messages

3. Session Screen
   - Header with imp identity (session short, ip, user, os)
   - Large Output pane (scrollable, preserves up to N lines, e.g. 1000)
   - Command input with help hint; Enter sends
   - Background task: periodic `retrieve_all_out` and distribute new lines; handle getfile special-case decoding and save to `loot/` (same logic as TUI)
   - Commands: same set as TUI; special flows for `sendfile`, `bof`, `inject`, `runpe` to upload file first, then issue task with filename

4. Build Implant Dialog
   - Inputs: target_os, format, target_ip, target_port, sleep, jitter
   - Calls `/build_imp` and saves file following TUI extension rules

### Directory Layout
```
conduit_gui/
  Cargo.toml
  src/
    main.rs             // Dioxus app entry
    app.rs              // Router and global state
    models.rs           // ImpInfo and DTOs
    services/
      mod.rs
      api.rs            // Reqwest calls, header building
      output.rs         // decode logic, loot saving
      build.rs          // build_imp, file save helper
      upload.rs         // bofload and file helpers
    components/
      login.rs
      dashboard.rs
      session.rs
      build_dialog.rs
    ui/
      table.rs          // table helpers/styles if needed
```

### Step-by-Step Implementation (LLM-friendly tasks)

1) Bootstrap crate [DONE]
- Created `conduit_gui/` with Dioxus Desktop, Tokio, Reqwest, Serde, Config, Base64, RFD; added release profile similar to `conduit`.
- Implemented runnable Desktop entry using `dioxus_desktop::launch(App, vec![], Config::default())` with a minimal UI shell and CSS.

2) Shared models
- Create `models.rs` with `ImpInfo` struct matching TUI (serde derive).
- Add helper to compute short-session (last 8 chars).

3) Config loader
- Implement `services::config` that loads `conduit/config.toml` (port) and offers `append_port_if_missing(url, port)`.

4) API service layer [DONE - scaffold]
- `services::api` functions:
  - `authenticate(url, username, password) -> Result<String, Error>`
  - `fetch_imps(url, token) -> Result<Vec<ImpInfo>, Error>`
  - `issue_task(url, token, session_id, task) -> Result<(), Error>`
  - `retrieve_all_out(url, token) -> Result<String, Error>` (raw base64)
  - `build_imp(url, token, params) -> Result<Vec<u8>, Error>`
  - `bofload(url, token, filename, bytes) -> Result<(), Error>`
- All requests: `danger_accept_invalid_certs(true)` to mirror TUI
Notes: Implemented per TUI semantics; not yet wired into UI beyond login.

5) Output handling [DONE - scaffold]
- `services::output`:
  - `decode_output(raw: String) -> String` using URL_SAFE NO_PAD
  - Special-case `getfile` results: detect path and final base64 blob, decode and save to `loot/`, return friendly message path
  - Utility to split into lines and dedupe last-seen entry (match TUI’s previous_output check)
Notes: Added helpers; dedupe logic to be added when wiring session view.

6) File ops helpers [DONE - scaffold]
- `services::upload`:
  - `open_file_dialog() -> Option<(filename, bytes)>` via `rfd`
  - For `sendfile`, `inject`, `runpe`, `bof` upload flow: return server filename (basename) for task string

7) Global app state and routing
- `app.rs` with a shared `AppState` context:
  - `token: Option<String>`
  - `base_url: String`
  - `imps: Vec<ImpInfo>`
  - `output_lines: VecDeque<String>` (session page)
  - `connection_msg: Option<String>`
- Simple enum route: `Route::Login | Route::Dashboard | Route::Session { session_id, sleep, os }`
- Provide context and navigation helpers

8) Login component [DONE]
- Fields: URL, Username, Password (masked), submit button
- On submit: load port from config, append if needed; call `authenticate`, store token + url, navigate to Dashboard
- Handle error display
Notes: Implemented inline within `App` for now to reduce boilerplate. Will refactor into `components::login` later if needed.

9) Dashboard component [DONE - basic]
- Implemented polling each second using `use_future(move || async move { ... })` and updating a signal-backed list.
- Rendered table with columns matching TUI and a stale/fresh color rule (red after `sleep + 60s`).
- Row click handler stubbed for now; will route to Session in next step.
Notes: RSX requires owned rows for iteration; used `map(..)` to build row nodes and inserted iterator directly in `tbody`.

10) Session component
- Show imp header and a scrollable output area; cap to 1000 lines
- Command input with help hints (contextual to OS: windows/linux/generic as in TUI)
- Background poller: every N seconds (see logic below) call `retrieve_all_out`, decode, split, push lines into output (skip dupes)
- Command handling:
  - Direct tasks: `whoami`, `ipconfig`, `ps`, `cd`, `pwd`, `ls`, `catfile`, `cmd`, `pwsh`, `sh`, `wmi`, `socks`, `sleep`, `kill`, `q|quit`
  - `sendfile`/`bof`/`inject`/`runpe`: open file dialog, upload file via `bofload`, then issue task text with just filename (and any args)
  - On `q|quit`: navigate back to Dashboard

11) Poll timing logic (match TUI behavior)
- For dashboard imps polling: fixed 1-second interval
- For session output polling: choose interval equal to min(imp.sleep) from dashboard data or a default (3s) if unknown; add jitter behavior later if needed

12) Build dialog
- Fields: `target_os`, `format`, `target_ip`, `target_port`, `sleep`, `jitter`
- Submit calls `build_imp`, then save bytes to a file:
  - Windows: `.exe` for `exe`, `.dll` for `dll`, `.bin` for `raw`
  - Linux: no extension (match TUI)
- Show completion toast with file path

13) Loot folder
- Ensure `loot/` exists at app start; write downloads there as TUI does

14) Error handling & UX
- Show inline errors (auth, network) and a reconnect message when connectivity resumes (replicate TUI’s "Connection re-established")
- Prevent duplicate output lines; keep last N

15) Testing strategy
- Unit tests for `services::output::decode_output` and getfile parsing/save
- Smoke-tests for API layer behind a feature flag or mock server
- Manual E2E against Anvil

16) Packaging & Run
- `cargo run -p conduit_gui`
- Later: produce single-file binaries for Windows/Linux/macOS

### Feature Parity Checklist
- [ ] Auth flow with Basic auth → token persisted in memory
- [ ] Dashboard imps list with coloring rule and scrolling
- [ ] Session view with command input and output scrolling (1000-line cap)
- [ ] Continuous output polling and dedupe
- [ ] All tasks supported; special upload flows for `sendfile`/`bof`/`inject`/`runpe`
- [ ] Build implant workflow and file save rules
- [ ] Config port append behavior
- [ ] Loot directory writes for getfile
- [ ] Connection status messages

### Initial Task Breakdown for Implementation
1. Create crate, deps, and hello-world Dioxus app
2. Add models and config loader
3. Implement API service functions (auth, fetch_imps)
4. Build Login component → wire auth
5. Build Dashboard with polling → render table
6. Implement Session view scaffolding → issue_task
7. Add retrieve_all_out polling and output decoding
8. Implement upload flows (`bofload`) + command wiring for `bof`/`inject`/`runpe`/`sendfile`
9. Implement Build dialog and saving rules
10. Polish UX: scrolling, toasts, errors, connection messages
11. Add tests for decode and file save helpers

### Notes
- Dioxus Desktop is chosen for simplicity and native-feel. If we later want Tauri packaging or a web build (Dioxus Web), the architecture isolates services and components to make that feasible.
- We mirror TUI’s permissive TLS handling for parity; consider hardening later.


