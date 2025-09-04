use dioxus::prelude::*;

#[component]
pub fn SocksDialog(on_close: EventHandler<()>, on_submit: EventHandler<String>) -> Element {
    let mut port = use_signal(|| String::from("1080"));

    rsx! {
        div { class: "modal_backdrop", onclick: move |_| on_close.call(()),
            div { class: "modal", onclick: move |e| e.stop_propagation(),
                h2 { "SOCKS" }
                div { class: "field", label { "Port" } input { value: "{port}", oninput: move |e| port.set(e.value()) } }
                div { class: "actions",
                    button { onclick: move |_| on_close.call(()), "Cancel" }
                    button { onclick: move |_| on_submit.call(port.read().clone()), "Start" }
                }
            }
        }
    }
}


