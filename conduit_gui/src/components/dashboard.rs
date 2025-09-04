use dioxus::prelude::*;
use crate::{AppState, Route};
use crate::services::api;
use crate::models::ImpInfo;
use chrono::{DateTime, NaiveDateTime, Utc};

#[component]
pub fn Dashboard(state: AppState) -> Element {
    let imps = use_signal(|| Vec::<ImpInfo>::new());
    let connection_msg = use_signal(|| None as Option<String>);
    let mut selected_index = use_signal(|| None as Option<usize>);
    let mut context_menu = use_signal(|| None as Option<(usize, i32, i32)>); // (row_idx, x, y)
    let mut sleep_target = use_signal(|| None as Option<usize>);
    let mut socks_target = use_signal(|| None as Option<usize>);
    let _dash_status = use_signal(|| None as Option<String>);

    // polling
    {
        let state_clone = state.clone();
        let mut imps_sig = imps.clone();
        let mut conn_sig = connection_msg.clone();
        use_future(move || async move {
            loop {
                if let (Some(tok), url) = (state_clone.token.read().clone(), state_clone.base_url.read().clone()) {
                    match api::fetch_imps(&url, tok.as_str()).await {
                        Ok(list) => {
                            *imps_sig.write() = list;
                            if conn_sig.read().is_some() {
                                *conn_sig.write() = Some("Connection re-established".to_string());
                            }
                        }
                        Err(e) => {
                            *conn_sig.write() = Some(format!("Error fetching imp info: {}", e));
                        }
                    }
                }
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
        });
    }

    let mut open_session = {
        let mut state_clone = state.clone();
        move |session: String, sleep: String, os: String| {
            *state_clone.selected_session.write() = Some(session.clone());
            *state_clone.route.write() = Route::Session { session_id: session, sleep, os };
        }
    };

    let rows_vec: Vec<ImpInfo> = imps.read().iter().cloned().collect();
    let status_msg = connection_msg.read().as_ref().cloned();
    let rows_iter = rows_vec.iter().cloned().enumerate().map(|(row_idx, imp)| {
        let sleep_secs = imp.sleep.parse::<u64>().unwrap_or(0);
        let last_dt: DateTime<Utc> = NaiveDateTime::parse_from_str(&imp.last_check_in, "%Y-%m-%d %H:%M:%S")
            .map(|naive| DateTime::from_naive_utc_and_offset(naive, Utc))
            .unwrap_or_else(|_| Utc::now());
        let diff = Utc::now().signed_duration_since(last_dt);
        let is_stale = diff.num_seconds() as u64 > sleep_secs + 60;
        let color_class = if is_stale { "stale" } else { "fresh" };

        let session = imp.session.clone();
        let sleep_s = imp.sleep.clone();
        let os = imp.os.clone();

        rsx!(
            tr { onclick: move |_| selected_index.set(Some(row_idx)),
                 ondoubleclick: move |_| open_session(session.clone(), sleep_s.clone(), os.clone()),
                 onmousedown: move |e| {
                    let pt = e.client_coordinates();
                    let x = pt.x as i32;
                    let y = pt.y as i32;
                    context_menu.set(Some((row_idx, x, y)));
                 },
                td { class: "{color_class}", "{imp.short_session()}" }
                td { class: "{color_class}", "{imp.ip}" }
                td { class: "{color_class}", "{imp.username}" }
                td { class: "{color_class}", "{imp.domain}" }
                td { class: "{color_class}", "{imp.os}" }
                td { class: "{color_class}", "{imp.imp_pid}" }
                td { class: "{color_class}", "{imp.process_name}" }
                td { class: "{color_class}", "{imp.sleep}" }
                td { class: "{color_class}", "{imp.last_check_in}" }
            }
        )
    });

    rsx! {
        div { class: "dashboard",
            if let Some(msg) = status_msg {
                div { class: "status", "{msg}" }
            }
            table { class: "imp_table",
                thead { tr {
                    th { "Session" }
                    th { "IP" }
                    th { "Username" }
                    th { "Domain" }
                    th { "OS" }
                    th { "PID" }
                    th { "Process" }
                    th { "Sleep" }
                    th { "Last Check In" }
                }}
                tbody { {rows_iter} }
            }
            {
                match *context_menu.read() {
                    Some((row_idx, x, y)) => {
                        if let Some(row_imp) = imps.read().get(row_idx).cloned() {
                            let sid = row_imp.session.clone();
                            let sleep = row_imp.sleep.clone();
                            let os = row_imp.os.clone();
                            let style_str = format!("left: {}px; top: {}px;", x, y);
                            let state_for_kill = state.clone();
                            let state_for_refresh = state.clone();
                            rsx!(
                                div { class: "ctxmenu", style: "{style_str}",
                                    div { class: "ctxitem", onclick: move |_| {
                                            open_session(sid.clone(), sleep.clone(), os.clone());
                                            context_menu.set(None);
                                        }, "Use Session" }
                                    div { class: "ctxitem", onclick: move |_| {
                                            sleep_target.set(Some(row_idx));
                                            context_menu.set(None);
                                        }, "Sleep…" }
                                    div { class: "ctxitem", onclick: move |_| {
                                            socks_target.set(Some(row_idx));
                                            context_menu.set(None);
                                        }, "SOCKS…" }
                                    div { class: "ctxitem", onclick: move |_| {
                                            if let (Some(tok), url) = (state_for_kill.token.read().clone(), state_for_kill.base_url.read().clone()) {
                                                let sid = row_imp.session.clone();
                                                spawn(async move {
                                                    let _ = api::issue_task(&url, tok.as_str(), &sid, "kill").await;
                                                });
                                            }
                                            context_menu.set(None);
                                        }, "Kill" }
                                    div { class: "ctxitem", onclick: move |_| {
                                            let state_clone = state_for_refresh.clone();
                                            let mut imps_sig = imps.clone();
                                            spawn(async move {
                                                if let (Some(tok), url) = (state_clone.token.read().clone(), state_clone.base_url.read().clone()) {
                                                    if let Ok(list) = api::fetch_imps(&url, tok.as_str()).await {
                                                        *imps_sig.write() = list;
                                                    }
                                                }
                                            });
                                            context_menu.set(None);
                                        }, "Refresh" }
                                    div { class: "ctxclose", onclick: move |_| context_menu.set(None), "Close" }
                                }
                            )
                        } else {
                            rsx!(div {})
                        }
                    }
                    None => rsx!(div {})
                }
            }
            {
                if let Some(idx) = *sleep_target.read() {
                    if let Some(imp) = imps.read().get(idx).cloned() {
                        let sid = imp.session.clone();
                        let state_sleep = state.clone();
                        let sid_sleep = sid.clone();
                        let on_close_sleep = {
                            let mut sleep_target_local = sleep_target.clone();
                            move |_| sleep_target_local.set(None)
                        };
                        let on_submit_sleep = {
                            let state_sleep2 = state_sleep.clone();
                            let sid_sleep2 = sid_sleep.clone();
                            let mut sleep_target_local = sleep_target.clone();
                            move |(secs, jit)| {
                                if let (Some(tok), url) = (state_sleep2.token.read().clone(), state_sleep2.base_url.read().clone()) {
                                    let sid_local = sid_sleep2.clone();
                                    spawn(async move {
                                        let task = format!("sleep {} {}", secs, jit);
                                        let _ = api::issue_task(&url, tok.as_str(), &sid_local, &task).await;
                                    });
                                }
                                sleep_target_local.set(None);
                            }
                        };
                        rsx!(
                            crate::components::sleep_dialog::SleepDialog {
                                on_close: on_close_sleep,
                                on_submit: on_submit_sleep
                            }
                        )
                    } else { rsx!(div {}) }
                } else { rsx!(div {}) }
            }
            {
                if let Some(idx) = *socks_target.read() {
                    if let Some(imp) = imps.read().get(idx).cloned() {
                        let sid = imp.session.clone();
                        let state_socks = state.clone();
                        let sid_socks = sid.clone();
                        let on_close_socks = {
                            let mut socks_target_local = socks_target.clone();
                            move |_| socks_target_local.set(None)
                        };
                        let on_submit_socks = {
                            let state_socks2 = state_socks.clone();
                            let sid_socks2 = sid_socks.clone();
                            let mut socks_target_local = socks_target.clone();
                            move |port| {
                                if let (Some(tok), url) = (state_socks2.token.read().clone(), state_socks2.base_url.read().clone()) {
                                    let sid_local = sid_socks2.clone();
                                    spawn(async move {
                                        let task = format!("socks {}", port);
                                        let _ = api::issue_task(&url, tok.as_str(), &sid_local, &task).await;
                                    });
                                }
                                socks_target_local.set(None);
                            }
                        };
                        rsx!(
                            crate::components::socks_dialog::SocksDialog { on_close: on_close_socks, on_submit: on_submit_socks }
                        )
                    } else { rsx!(div {}) }
                } else { rsx!(div {}) }
            }
        }
    }
}


