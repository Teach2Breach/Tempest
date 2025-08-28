## Tempest Conduit GUI – Feature Implementation Plan

Context: The GUI is built with Dioxus Desktop. Current capabilities:
- Login screen with URL/username/password and config-driven port append.
- Dashboard table listing imps with live polling and stale/fresh coloring.
- No session view yet; no command input/output panes; no context actions.

Goal: Achieve feature parity with Conduit TUI while providing GUI affordances:
- Click/Right-click actions on dashboard rows (select, use session, kill, etc.).
- Session view with output pane and command input.
- File upload flows (sendfile, bof, inject, runpe) via file pickers.
- Build implants via a dialog.
- Custom window chrome (no native toolbar) and app menu.
- Robust error/status messaging and connection state indications.

Assumptions & Interfaces
- Server (Anvil) endpoints (HTTPS on conduit port):
  - POST /authenticate (Basic auth) → token string
  - GET /imps (X-Token) → Vec<ImpInfo>
  - POST /issue_task (x-token, x-session, x-task)
  - GET /retrieve_all_out (x-token) → base64(URL_SAFE, NO_PAD) payloads
  - POST /bofload (binary upload) with headers X-Token and X-Filename
  - POST /build_imp (headers x-token, x-target, x-target-ip, x-target-port, x-tsleep, x-format, x-jitter) → bytes
- ImpInfo fields (ordered): session, ip, username, domain, os, imp_pid, process_name, sleep, last_check_in.
- Output retrieval cadence follows min sleep or default 3s.

High-Level UX
1) Frameless window with custom top bar and application menu.
2) Login screen → Dashboard upon success.
3) Dashboard: table of imps; row click selects; right-click opens context menu:
   - Use session
   - Kill
   - Sleep… (opens small dialog)
   - SOCKS… (port prompt)
   - Build… (global action in top bar as well)
   - Refresh
4) Session view: header with imp details; split panes: output (top), command input (bottom). Buttons for common actions; context menu in output pane for copy/clear.
5) File upload actions show picker and flow automatically (bof/inject/runpe/sendfile).

Architecture Changes
- State: Introduce `AppContext` (via Dioxus context) to hold:
  - base_url, token, selected_session, selected_imp (lookup), last_known_imps
  - output buffer (VecDeque<String>), max lines
  - connection status messages
- Routing: `Route::Login | Route::Dashboard | Route::Session { session_id }`.
- Services: existing api.rs (auth, imps, issue_task, retrieve_all_out, build_imp, bofload) are sufficient; add small helpers for composed actions.
- UI: components
  - shell.rs (frameless window chrome, menus)
  - dashboard.rs (table + context menu + actions)
  - session.rs (output + input + quick action buttons)
  - dialogs/: build_dialog.rs, sleep_dialog.rs, socks_dialog.rs, confirm_dialog.rs
  - widgets/: context_menu.rs, status_toast.rs

Feature Mapping (TUI → GUI)
- help: surfaced via menu and in-session help modal.
- build: dialog with fields, success saves file to cwd and shows toast.
- use <session>: row right-click → Use; or double-click row.
- q/quit session: back button from session.
- whoami/ipconfig/ps/cd/pwd/ls/catfile: via command input; optionally quick buttons for whoami/ipconfig/ps.
- getfile: no change; prints “File saved to: …” in output.
- sendfile: file picker; encode + issue; display result.
- cmd/pwsh/sh/wmi: from command input.
- bof/inject/runpe: file picker → upload → issue task with filename; show status.
- socks: dialog asks for port (and IP if needed) → issue task; show status.
- sleep: dialog asks seconds and jitter → issue; reflects in dashboard next poll.
- kill: confirmation dialog → issue; remove row upon next poll.

Detailed Step-by-Step Tasks (LLM-friendly)

Phase 1: UI Shell & Navigation
1. Add frameless window: configure Dioxus Desktop to hide native toolbar and draw custom top bar (title, window controls: minimize/close). Provide keyboard shortcuts for menu (Alt key).
2. Create `AppContext` with signals for: base_url, token, route, selected_session, imps, output buffer, connection_msg.
3. Implement router in `App` to switch among Login/Dashboard/Session inside a shell with menu.

Phase 2: Dashboard Interactions
4. Enhance dashboard table: store selected row index; on row click select; on double-click navigate to session.
5. Add right-click context menu component bound to row coordinate:
   - Use Session → set selected_session and go to Session.
   - Kill → confirm dialog; on confirm call issue_task("kill").
   - Sleep… → dialog (seconds, jitter) → issue_task("sleep <s> <jitter>").
   - SOCKS… → dialog (port) → issue_task("socks <port>").
   - Refresh → force one fetch cycle.
6. Add build button in top bar; opens Build dialog.

Phase 3: Session View
7. Create session.rs with layout: header (session short, ip, os), output pane (scrollable, grows up to N lines), command input at bottom.
8. Poll outputs: coroutine on entering session calls retrieve_all_out periodically, decodes URL_SAFE NO_PAD base64; split lines and append; save files for getfile.
9. Command input handling: on Enter, parse; for special flows:
   - sendfile/bof/inject/runpe → open file picker; upload via bofload; rewrite command with basename; issue_task.
   - everything else → issue_task(command_text).
10. Add quick action buttons: whoami, ps, ipconfig, sleep (dialog), kill (confirm), socks (dialog).
11. Add errors/success toasts; show “Connection re-established” when polling recovers.

Phase 4: Build Dialog
12. Implement dialog with fields: target_os, format, target_ip, target_port, sleep, jitter. Validate input.
13. Call build_imp; save bytes to filename (same convention as TUI); show success toast and open-folder option.

Phase 5: Polish & Settings
14. Add settings modal to edit base URL and persist last-used URL; allow switching between http/https if ever needed.
15. Theming tweaks (light/dark) and responsive table column widths; ensure keyboard navigation in table and output.
16. Logging pane (optional) to display internal errors and request statuses for troubleshooting.

Testing Plan
- Local E2E against Anvil stub or dev server.
- File flows (bof/inject/runpe/sendfile/getfile) verified with real uploads and downloads.
- Sleep change reflected in dashboard color logic.
- Reconnect scenarios: server restart during session; ensure UI recovers and continues polling.

Risks & Mitigations
- Different server shapes (8 vs 9 fields): GUI strictly expects object; if needed, reintroduce tolerant mapping.
- Large outputs: cap output buffer; provide clear/export.
- Context menu interactions: ensure they’re keyboard accessible.

Implementation Notes (Code Pointers)
- services/api.rs: already has authenticate, fetch_imps, issue_task, retrieve_all_out, build_imp, bofload.
- services/cfg.rs: port loading now checks current dir config first.
- dashboard.rs: extend with selection and context menu; reuse fetch loop.
- session.rs: new polling coroutine and command flow.
- dialogs/: build, sleep, socks; widgets/: context_menu, status_toast.

Milestones
M1: Dashboard selection + context menu + Build dialog skeleton.
M2: Session view with output polling + command input (basic).
M3: File flows & quick actions.
M4: Frameless window + custom menu.
M5: Polish, error handling, settings.


