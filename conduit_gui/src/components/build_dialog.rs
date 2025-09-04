use dioxus::prelude::*;
use tokio::fs::File as TokioFile;
use tokio::io::AsyncWriteExt;

#[component]
pub fn BuildDialog(on_close: EventHandler<()>, base_url: String, token: Option<String>) -> Element {
    let mut target = use_signal(|| String::from("windows"));
    let mut format = use_signal(|| String::from("exe"));
    let mut target_ip = use_signal(|| String::new());
    let mut target_port = use_signal(|| String::from("8443"));
    let mut tsleep = use_signal(|| String::from("3"));
    let mut jitter = use_signal(|| String::from("10"));
    let status_msg = use_signal(|| None as Option<String>);
    let is_building = use_signal(|| false);

    let on_build = {
        let base = base_url.clone();
        let tok = token.clone();
        let mut status = status_msg.clone();
        let mut building = is_building.clone();
        move |_| {
            if tok.is_none() {
                *status.write() = Some("Not authenticated".to_string());
                return;
            }
            let token_str = tok.clone().unwrap();
            let base_clone = base.clone();
            let tgt = target.read().clone();
            let fmt = format.read().clone();
            let ip = target_ip.read().clone();
            let port = target_port.read().clone();
            let slp = tsleep.read().clone();
            let jit = jitter.read().clone();
            building.set(true);
            spawn(async move {
                match crate::services::api::build_imp(&base_clone, &token_str, &tgt, &ip, &port, &slp, &fmt, &jit).await {
                    Ok(bytes) => {
                        // Derive filename similarly to TUI rules
                        let filename = if tgt.contains("windows") {
                            match fmt.as_str() {
                                "exe" => format!("{}.exe", tgt),
                                "dll" => format!("{}.dll", tgt),
                                "raw" => format!("{}.bin", tgt),
                                _ => format!("{}.exe", tgt),
                            }
                        } else {
                            tgt.clone()
                        };
                        let path = filename;
                        let mut f = match TokioFile::create(&path).await {
                            Ok(f) => f,
                            Err(e) => {
                                *status.write() = Some(format!("Failed to create file: {}", e));
                                building.set(false);
                                return;
                            }
                        };
                        if let Err(e) = f.write_all(&bytes).await { 
                            *status.write() = Some(format!("Failed to write file: {}", e));
                            building.set(false);
                            return;
                        }
                        *status.write() = Some(format!("Build complete. Saved to {}", path));
                        building.set(false);
                    }
                    Err(e) => {
                        *status.write() = Some(format!("Build failed: {}", e));
                        building.set(false);
                    }
                }
            });
        }
    };

    rsx! {
        div { class: "modal_backdrop", onclick: move |_| on_close.call(()),
            div { class: "modal", onclick: move |e| e.stop_propagation(),
                h2 { "Build Implant" }
                div { class: "field", label { "Target OS" } input { value: "{target}", oninput: move |e| target.set(e.value()) } }
                div { class: "field", label { "Format" } input { value: "{format}", oninput: move |e| format.set(e.value()) } }
                div { class: "field", label { "Target IP" } input { value: "{target_ip}", oninput: move |e| target_ip.set(e.value()) } }
                div { class: "field", label { "Target Port" } input { value: "{target_port}", oninput: move |e| target_port.set(e.value()) } }
                div { class: "field", label { "Sleep (s)" } input { value: "{tsleep}", oninput: move |e| tsleep.set(e.value()) } }
                div { class: "field", label { "Jitter (%)" } input { value: "{jitter}", oninput: move |e| jitter.set(e.value()) } }
                if let Some(msg) = &*status_msg.read() { div { class: "status", "{msg}" } }
                div { class: "actions",
                    button { onclick: move |_| on_close.call(()), "Close" }
                    button { disabled: *is_building.read(), onclick: on_build, "Build" }
                }
            }
        }
    }
}


