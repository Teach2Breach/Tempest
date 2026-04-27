# `conduit_gui` — operator GUI (Dioxus)

Primary operator client for Tempest. See root `README.md`, `gui_plan.md`, and `techplan.md`.

## System packages (required to link the GUI on Linux)

`conduit_gui` pulls in **WebKitGTK 4.1**, **GTK 3**, **libsoup**, **JavaScriptCore**, and other GNOME stack libraries. Install the development packages for your distro **before** `cargo build`.

### Debian / Ubuntu / Pop!_OS

```bash
sudo apt update
sudo apt install -y \
  build-essential \
  pkg-config \
  libssl-dev \
  libwebkit2gtk-4.1-dev \
  libgtk-3-dev \
  libayatana-appindicator3-dev \
  libxdo-dev \
  librsvg2-dev \
  curl \
  wget \
  file
```

- **`libwebkit2gtk-4.1-dev`** — WebKit (required by the desktop renderer; errors like “Package `gobject-2.0` / `javascriptcoregtk-4.1` not found” are fixed by the GTK/WebKit stack above).
- **`libgtk-3-dev`** — GTK3 headers and `pkg-config` files for `gdk-3.0`, `glib-2.0`, `cairo`, `pango`, etc.
- **`libayatana-appindicator3-dev`** — tray / app indicator (often pulled by Tauri/Wry-style Linux builds).
- **`libssl-dev`** — OpenSSL (Rust `openssl` crate).
- **`libxdo-dev`** — X11 automation (`xdotool`-style; some desktop stacks expect it).
- **`build-essential`** — `gcc`, `g++`, `make`.

On **Ubuntu 22.04+** you generally want **4.1** WebKit (as above). Very old distros may use different `webkit2gtk` package names; if `libwebkit2gtk-4.1-dev` is missing, check your release’s package search for `webkit2gtk`.

### Fedora

```bash
sudo dnf install @development-tools
sudo dnf install \
  pkg-config \
  openssl-devel \
  gtk3-devel \
  webkit2gtk4.1-devel \
  libappindicator-gtk3-devel \
  libxdo-devel \
  librsvg2-devel
```

### Arch Linux

```bash
sudo pacman -S --needed \
  base-devel \
  pkgconf \
  openssl \
  gtk3 \
  webkit2gtk-4.1 \
  libayatana-appindicator \
  libxdo \
  librsvg
```

## Build

From this directory:

```bash
../scripts/cargo-ide.sh build --release
```

If your editor shows `error: unknown proxy name: 'Cursor'` when using plain `cargo`, use `../scripts/cargo-ide.sh` (or point `RUSTC` / `RUSTDOC` / `PATH` at the stable toolchain’s `bin/` as that script does).

Optional — check Dioxus tooling: `dx doctor` (if you have the Dioxus CLI installed).

### Rust / `cargo` notes

- **IDE rustup shim:** If `error: unknown proxy name: 'Cursor'`, use `../scripts/cargo-ide.sh` (see repository root and `docs/BUILDING.md`).
- **Future-incompatibility (`ashpd`):** `dioxus-desktop` pulls **`rfd` 0.14**, which depends on **`ashpd` 0.8.x** for Linux xdg-portal. That crate can emit a **never-type fallback** notice (`cargo build` / `cargo report future-incompatibilities`). It is **transitive** — Tempest’s own code does not depend on `ashpd` directly. The practical fix is to **upgrade the stack** when `dioxus` / `dioxus-desktop` / `rfd` publish versions that use a newer `ashpd` (or a fork applies the compiler’s suggested `()` annotations on 0.8). Until then, the project stays on **Rust edition 2021**; re-check after dependency bumps.
- If you add a *direct* `rfd` dependency, keep it aligned with `dioxus-desktop`: `default-features = false`, `features = ["xdg-portal", "tokio"]` — otherwise both `ashpd`’s `async-std` and `tokio` features can be enabled and the build **fails**.

## Other crates in this repo

- **`Anvil`** and **`conduit`** (TUI) are normal Rust/cargo builds; they do **not** need the WebKit/GTK stack. A typical Rust setup plus `libssl-dev` (Debian) / `openssl-devel` (Fedora) is enough for HTTPS/OpenSSL.
- Only **`conduit_gui`** needs the full desktop list above.
