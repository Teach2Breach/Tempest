compile dll with:
cargo rustc --lib --release -- -C relocation-model=pic

compile exe with: 
cargo rustc --bin invoke_imp --release -- -C relocation-model=pic