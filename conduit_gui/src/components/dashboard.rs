use dioxus::prelude::*;
use crate::{AppState};
use crate::services::api;
use crate::models::ImpInfo;
use chrono::{DateTime, NaiveDateTime, Utc};

#[component]
pub fn Dashboard(state: AppState) -> Element {
    let imps = use_signal(|| Vec::<ImpInfo>::new());
    let connection_msg = use_signal(|| None as Option<String>);

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

    let open_session = { move |_session: String, _sleep: String, _os: String| { /* placeholder */ } };

    let rows_vec: Vec<ImpInfo> = imps.read().iter().cloned().collect();
    let status_msg = connection_msg.read().as_ref().cloned();
    let rows_iter = rows_vec.into_iter().map(|imp| {
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
            tr { onclick: move |_| open_session(session.clone(), sleep_s.clone(), os.clone()),
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
        }
    }
}


