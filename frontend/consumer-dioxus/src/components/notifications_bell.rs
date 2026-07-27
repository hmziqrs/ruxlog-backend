//! Consumer notification bell.
//!
//! Shown in the consumer navbar (only when `consumer-auth` is enabled and the
//! user is logged in). Polls the unread count on mount, renders a bell with a
//! live badge, and opens a dropdown of recent notifications on click. Marking
//! all read (or clicking an unread row) refreshes both the list and the badge.

use dioxus::prelude::*;
use ruxlog_shared::{use_notification, NotificationItem};

/// Bell icon with an unread-count badge plus a dropdown of recent notifications.
///
/// Feature-gated behind `consumer-auth` because it requires an authenticated
/// session — the navbar only renders it for logged-in users. All network state
/// lives in the shared `notification` store so the badge stays in sync with the
/// admin "In-App" indicator and any other reader of `use_notification()`.
#[component]
pub fn NotificationsBell() -> Element {
    let notifications = use_notification();
    let mut dropdown_open = use_signal(|| false);
    let mut loaded_list = use_signal(|| false);

    // Poll the unread count on mount.
    use_effect(move || {
        let notifications = use_notification();
        spawn(async move {
            notifications.unread_count().await;
        });
    });

    // Live unread count (reactive read of the store).
    let unread_frame = notifications.unread_count.read();
    let unread: u64 = unread_frame.data.as_ref().map(|u| u.count).unwrap_or(0);
    let unread_loading = unread_frame.is_loading();

    // List state for the dropdown.
    let list_frame = notifications.list.read();
    let list_loading = list_frame.is_loading();
    let items: Vec<NotificationItem> = list_frame
        .data
        .as_ref()
        .map(|page| page.data.clone())
        .unwrap_or_default();

    let toggle_dropdown = move |_: MouseEvent| {
        let now_open = !*dropdown_open.read();
        dropdown_open.set(now_open);
        if now_open && !*loaded_list.read() {
            loaded_list.set(true);
            let notifications = use_notification();
            spawn(async move {
                notifications.list(1, 20).await;
            });
        }
    };

    let on_mark_all_read = move |_: MouseEvent| {
        let notifications = use_notification();
        spawn(async move {
            notifications.mark_all_read().await;
            notifications.list(1, 20).await;
            notifications.unread_count().await;
        });
    };

    rsx! {
        div { class: "relative",
            button {
                onclick: toggle_dropdown,
                class: "icon-button relative",
                aria_label: "Notifications",
                // Inline SVG bell (avoids an extra icon-crate import).
                svg {
                    xmlns: "http://www.w3.org/2000/svg",
                    width: "20",
                    height: "20",
                    view_box: "0 0 24 24",
                    fill: "none",
                    stroke: "currentColor",
                    "stroke-width": "2",
                    "stroke-linecap": "round",
                    "stroke-linejoin": "round",
                    path { d: "M6 8a6 6 0 0 1 12 0c0 7 3 9 3 9H3s3-2 3-9" }
                    path { d: "M10.3 21a1.94 1.94 0 0 0 3.4 0" }
                }
                if unread > 0 {
                    span {
                        class: "absolute -top-0.5 -right-0.5 min-w-[18px] h-[18px] px-1 \
                                rounded-full bg-red-500 text-white text-[10px] font-semibold \
                                flex items-center justify-center",
                        "{unread}"
                    }
                } else if unread_loading {
                    span {
                        class: "absolute -top-0.5 -right-0.5 w-2 h-2 rounded-full \
                                bg-muted-foreground/50 animate-pulse"
                    }
                }
            }

            if *dropdown_open.read() {
                div {
                    class: "absolute right-0 mt-2 w-80 max-h-96 overflow-y-auto \
                            rounded-lg border border-border bg-card shadow-lg z-50",
                    div {
                        class: "flex items-center justify-between px-4 py-3 border-b \
                                border-border",
                        span { class: "text-sm font-semibold", "Notifications" }
                        if unread > 0 {
                            button {
                                onclick: on_mark_all_read,
                                class: "text-xs text-primary hover:underline",
                                "Mark all read"
                            }
                        }
                    }

                    if list_loading && items.is_empty() {
                        div {
                            class: "px-4 py-6 text-sm text-muted-foreground text-center",
                            "Loading..."
                        }
                    } else if items.is_empty() {
                        div {
                            class: "px-4 py-6 text-sm text-muted-foreground text-center",
                            "You're all caught up"
                        }
                    } else {
                        for item in &items {
                            NotificationRow { key: "{item.id}", item: item.clone() }
                        }
                    }
                }
            }
        }
    }
}

/// One row in the notifications dropdown. Clicking an unread row marks it read.
#[component]
fn NotificationRow(item: NotificationItem) -> Element {
    let is_unread = !item.is_read();
    let id = item.id;
    let row_class = format!(
        "px-4 py-3 border-b border-border last:border-b-0 hover:bg-muted/50{}",
        if is_unread { " cursor-pointer" } else { "" }
    );
    rsx! {
        div {
            class: "{row_class}",
            onclick: move |_| {
                if is_unread {
                    spawn(async move {
                        let notifications = use_notification();
                        notifications.mark_read(id).await;
                        notifications.list(1, 20).await;
                        notifications.unread_count().await;
                    });
                }
            },
            div { class: "flex items-start gap-2",
                if is_unread {
                    span { class: "mt-1.5 w-2 h-2 rounded-full bg-primary shrink-0" }
                } else {
                    span { class: "mt-1.5 w-2 h-2 rounded-full bg-transparent shrink-0" }
                }
                div { class: "min-w-0 flex-1 space-y-0.5",
                    if !item.title.is_empty() {
                        p { class: "text-sm font-medium truncate", "{item.title}" }
                    }
                    if !item.body.is_empty() {
                        p { class: "text-xs text-muted-foreground line-clamp-2",
                            "{item.body}"
                        }
                    }
                    if !item.kind.is_empty() {
                        p { class: "text-[10px] text-muted-foreground/70 uppercase \
                                   tracking-wide",
                            "{item.kind}"
                        }
                    }
                }
            }
        }
    }
}
