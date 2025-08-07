use dioxus::prelude::*;
use dioxus_desktop::launch::launch;
use dioxus_desktop::Config as DesktopConfig;

mod models;
mod services;
mod components {
    pub mod dashboard;
}

#[derive(Clone, PartialEq)]
enum Route {
    Login,
    Dashboard,
}

#[derive(Clone, PartialEq)]
struct AppState {
    base_url: Signal<String>,
    token: Signal<Option<String>>,
    route: Signal<Route>,
}

fn main() {
    launch(App, vec![], DesktopConfig::default());
}

#[component]
fn App() -> Element {
    // global signals
    let base_url = use_signal(|| String::new());
    let token = use_signal(|| None as Option<String>);
    let route = use_signal(|| Route::Login);

    let state = AppState { base_url, token, route };

    // local login signals
    let mut url = use_signal(|| String::new());
    let mut username = use_signal(|| String::new());
    let mut password = use_signal(|| String::new());
    let mut error = use_signal(|| None as Option<String>);

    let on_submit = {
        let mut state_clone = state.clone();
        move |_| {
            let url_val = url.read().clone();
            let username_val = username.read().clone();
            let password_val = password.read().clone();
            spawn(async move {
                let mut base = url_val;
                if let Some(port) = services::cfg::load_server_port() {
                    base = services::cfg::append_port_if_missing(base, port);
                }
                match services::api::authenticate(&base, &username_val, &password_val).await {
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
        style { "{include_str!(\"./styles.css\")}", }
        div { class: "root",
            header { class: "app_header", h1 { "Tempest Conduit GUI" } }
            main { class: "app_main",
                match *state.route.read() {
                    Route::Login => rsx!(
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
                    ),
                    Route::Dashboard => rsx!(components::dashboard::Dashboard { state: state.clone() }),
                }
            }
        }
    }
}



