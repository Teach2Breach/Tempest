use dioxus::prelude::*;

#[component]
pub fn SleepDialog(on_close: EventHandler<()>, on_submit: EventHandler<(String, String)>) -> Element {
    let mut seconds = use_signal(|| String::from("3"));
    let mut jitter = use_signal(|| String::from("10"));

    rsx! {
        div { class: "modal_backdrop", onclick: move |_| on_close.call(()),
            div { class: "modal", onclick: move |e| e.stop_propagation(),
                h2 { "Sleep" }
                div { class: "field", label { "Seconds" } input { value: "{seconds}", oninput: move |e| seconds.set(e.value()) } }
                div { class: "field", label { "Jitter (%)" } input { value: "{jitter}", oninput: move |e| jitter.set(e.value()) } }
                div { class: "actions",
                    button { onclick: move |_| on_close.call(()), "Cancel" }
                    button { onclick: move |_| on_submit.call((seconds.read().clone(), jitter.read().clone())), "Apply" }
                }
            }
        }
    }
}


