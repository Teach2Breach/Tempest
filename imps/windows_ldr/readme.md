compile dll with:
cargo rustc --lib --release -- -C relocation-model=pic

compile exe with: 
cargo rustc --bin rawimp_dev_copy --release -- -C relocation-model=pic

cross-compilation command (testing - requires cross, podman, and Cross.toml):
cross rustc --bin rawimp_dev_copy --target x86_64-pc-windows-gnu --release -- -C relocation-model=pic