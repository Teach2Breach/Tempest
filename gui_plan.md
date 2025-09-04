## Tempest Conduit GUI – Living Implementation Plan (Numbered Checklist)

1. Context and Capabilities
   1.1. GUI built with Dioxus Desktop.
   1.2. Current capabilities:
        - Login screen with URL/username/password and config-driven port append. [complete]
        - Dashboard table listing imps with live polling and stale/fresh coloring. [complete]
        - Frameless window with custom top bar (title, minimize/close). [complete]
        - Build dialog wired end-to-end (build_imp, save file, status). [complete]
        - Session view: header, output list, command input. [complete]
        - Terminal consoles: Dashboard global console and Session console. [complete]
        - Session polling/decoding (URL_SAFE NO_PAD) and getfile save. [complete]

2. Server Interfaces (Anvil) [complete]
   2.1. POST /authenticate (Basic) → token string
   2.2. GET /imps (X-Token) → Vec<ImpInfo>
   2.3. POST /issue_task (x-token, x-session, x-task)
   2.4. GET /retrieve_all_out (x-token) → base64 URL_SAFE NO_PAD
   2.5. POST /bofload (X-Token, X-Filename; body: binary)
   2.6. POST /build_imp (x-token, x-target, x-target-ip, x-target-port, x-tsleep, x-format, x-jitter) → bytes
   2.7. ImpInfo fields (ordered): session, ip, username, domain, os, imp_pid, process_name, sleep, last_check_in.

3. Dashboard Interactions
   3.1. Row selection on click; open session on double-click. [complete]
   3.2. Right-click context menu with actions: [complete]
        - Use Session
        - Sleep… (dialog → issue_task("sleep <s> <jitter>"))
        - SOCKS… (dialog → issue_task("socks <port>"))
        - Kill (issue_task("kill"))
        - Refresh (force fetch)
   3.3. Build button in top bar; opens Build dialog. [complete]
   3.4. Terminal-style console at bottom of Dashboard to accept text commands
        (e.g., "use <session>", help, refresh), mirroring TUI global input. [complete]

4. Session View
   4.1. Layout: header (session short, ip, os), output pane, command input. [complete]
   4.2. Terminal-style console at bottom for entering text commands (primary
        interaction path, matches TUI semantics). [complete]
   4.3. Poll retrieve_all_out periodically; decode URL_SAFE NO_PAD; split lines and append; save getfile payloads to loot/. [complete]
   4.4. Command input handling: generic issue_task(command) except local commands (help, q/quit) handled client-side. [complete]
   4.5. Special flows (sendfile/bof/inject/runpe): open file picker → upload via bofload → issue task with basename. [pending]
   4.6. Quick action buttons: whoami, ipconfig, ps, sleep (dialog), socks (dialog), kill (confirm). [pending]
   4.7. Errors/success toasts; connection re-established message. [pending]

5. Build Dialog
   5.1. Fields: target_os, format, target_ip, target_port, sleep, jitter. [complete]
   5.2. Call build_imp; save bytes to filename (OS/format rules). [complete]
   5.3. Show success status in dialog; optionally add open-folder action. [in_progress]

6. Polish & Settings
   6.1. Settings modal to edit/persist base URL; toggle http/https (if needed). [pending]
   6.2. Theming tweaks and responsive table widths; keyboard navigation for table/output. [pending]
   6.3. Optional logging pane for internal errors and request statuses. [pending]

7. Testing Plan
   7.1. Local E2E against Anvil.
   7.2. Verify file flows with real uploads/downloads.
   7.3. Sleep change reflected in dashboard color logic.
   7.4. Reconnect scenarios (server restart) handled gracefully.

8. Status Summary (This Session)
   8.1. Implemented frameless top bar and Build button.
   8.2. Built Build dialog and wired server call to generate implant; file saved with proper extension; verified working.
   8.3. Enhanced Dashboard: selection, double-click to session, context menu (Use, Sleep, SOCKS, Kill, Refresh).
   8.4. Added Sleep and SOCKS dialogs; actions issue tasks accordingly.
   8.5. Session consoles and Dashboard console implemented; help/q handled locally; commands issue tasks as in TUI; output polling/decoding with getfile save working.

9. Next Steps
   9.1. Add quick action buttons in Session (whoami, ipconfig, ps, sleep, socks, kill).
   9.2. Complete file flows (sendfile/bof/inject/runpe) with pickers/uploads and basename rewrite.
   9.3. Add toasts/status surface and connection recovery message.
   9.4. Add Settings modal and polish items (keyboard navigation, theming tweaks).
