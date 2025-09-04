use dioxus::prelude::*;
use dioxus_desktop::{self, Config, WindowBuilder};
use dioxus_desktop::use_window;
use dioxus_desktop::launch::launch;
use std::collections::VecDeque;

mod models;
mod services;
mod components {
    pub mod dashboard;
    pub mod build_dialog;
    pub mod sleep_dialog;
    pub mod socks_dialog;
    pub mod session;
}

#[derive(Clone, PartialEq)]
enum Route {
    Login,
    Dashboard,
    Session { session_id: String, sleep: String, os: String },
}

#[derive(Clone, PartialEq)]
struct AppState {
    base_url: Signal<String>,
    token: Signal<Option<String>>,
    route: Signal<Route>,
    selected_session: Signal<Option<String>>,
    connection_msg: Signal<Option<String>>,
    output_lines: Signal<VecDeque<String>>,
}

fn main() {
    let window = WindowBuilder::new()
        .with_title("Tempest Conduit GUI")
        .with_decorations(false)
        .with_inner_size(dioxus_desktop::LogicalSize::new(1280.0, 800.0))
        .with_min_inner_size(dioxus_desktop::LogicalSize::new(1024.0, 640.0));
    let cfg = Config::new().with_window(window);
    launch(App, vec![], vec![Box::new(cfg)]);
}

#[component]
fn App() -> Element {
    // global signals
    let base_url = use_signal(|| String::new());
    let token = use_signal(|| None as Option<String>);
    let route = use_signal(|| Route::Login);
    let selected_session = use_signal(|| None as Option<String>);
    let connection_msg = use_signal(|| None as Option<String>);
    let output_lines = use_signal(|| VecDeque::<String>::new());
    let win = use_window();

    let state = AppState { base_url, token, route, selected_session, connection_msg, output_lines };

    // local login signals
    let mut url = use_signal(|| String::new());
    let mut username = use_signal(|| String::new());
    let mut password = use_signal(|| String::new());
    let mut error = use_signal(|| None as Option<String>);
    let mut show_build_dialog = use_signal(|| false);

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
            header { class: "app_header",
                h1 { "Tempest Conduit GUI" }
                {
                    let win_min = win.clone();
                    let win_close = win.clone();
                    rsx!(
                        div { class: "topbar_actions",
                            button { class: "topbar_btn", onclick: move |_| show_build_dialog.set(true), "Build" }
                            button { class: "topbar_btn", onclick: {
                                let win = win_min.clone();
                                move |_| win.set_maximized(true)
                            }, "□" }
                            button { class: "topbar_btn", onclick: {
                                let win = win_min.clone();
                                move |_| win.set_minimized(true)
                            }, "_" }
                            button { class: "topbar_btn", onclick: move |_| win_close.close(), "×" }
                        }
                    )
                }
            }
            main { class: "app_main",
                {
                    let route_val = state.route.read().clone();
                    match route_val {
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
                    Route::Dashboard => rsx!(
                        div { class: "panes",
                            div { class: "pane_top_scroll", components::dashboard::Dashboard { state: state.clone() } }
                            div { class: "pane_bottom_scroll console_placeholder", "Select a session to begin." }
                        }
                    ),
                    Route::Session { session_id, sleep, os } => rsx!(
                        div { class: "panes",
                            div { class: "pane_top_scroll", components::dashboard::Dashboard { state: state.clone() } }
                            div { class: "pane_bottom_scroll", components::session::SessionView { state: state.clone(), session_id: session_id.clone(), sleep: sleep.clone(), os: os.clone() } }
                        }
                    ),
                    }
                }
            }
            if *show_build_dialog.read() {
                components::build_dialog::BuildDialog {
                    on_close: move |_| show_build_dialog.set(false),
                    base_url: state.base_url.read().clone(),
                    token: state.token.read().clone()
                }
            }
        }
    }
}




