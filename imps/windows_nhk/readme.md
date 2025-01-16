compile dll with:
cargo rustc --lib --release -- -C relocation-model=pic

compile exe with: 
cargo rustc --bin windows_nhk --release -- -C relocation-model=pic

cross-compilation command (testing - requires cross, podman, and Cross.toml):
cross rustc --bin windows_nhk --target x86_64-pc-windows-gnu --release -- -C relocation-model=pic