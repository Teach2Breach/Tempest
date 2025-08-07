use dioxus::prelude::*;
use crate::services::{api, cfg};

use crate::Route;
use crate::AppState;

#[component]
pub fn Login(state: AppState) -> Element {
    let url = use_signal(|| String::new());
    let username = use_signal(|| String::new());
    let password = use_signal(|| String::new());
    let error = use_signal(|| None as Option<String>);

    let on_submit = {
        let url = url.clone();
        let username = username.clone();
        let password = password.clone();
        let state_clone = state.clone();
        let error = error.clone();
        move |_| {
            let url_val = url.read().clone();
            let username_val = username.read().clone();
            let password_val = password.read().clone();

            spawn(async move {
                let mut base = url_val;
                if let Some(port) = cfg::load_server_port() {
                    base = cfg::append_port_if_missing(base, port);
                }

                match api::authenticate(&base, &username_val, &password_val).await {
                    Ok(tok) => {
                        *state_clone.base_url.write() = base;
                        *state_clone.token.write() = Some(tok);
                        *state_clone.route.write() = Route::Dashboard;
                    }
                    Err(e) => {
                        *error.write() = Some(format!("Login failed: {}", e));
                    }
                }
            });
        }
    };

    rsx! {
        div { class: "login",
            div { class: "field",
                label { "Server URL" }
                input { r#type: "text", value: "{url}", oninput: move |e| url.set(e.value()) }
            }
            div { class: "field",
                label { "Username" }
                input { r#type: "text", value: "{username}", oninput: move |e| username.set(e.value()) }
            }
            div { class: "field",
                label { "Password" }
                input { r#type: "password", value: "{password}", oninput: move |e| password.set(e.value()) }
            }
            div { class: "actions",
                button { onclick: on_submit, "Login" }
            }
            if let Some(err) = &*error.read() {
                div { class: "error", "{err}" }
            }
        }
    }
}


