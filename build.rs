use std::env;

fn main() {
    let encoded = env::var("CARGO_ENCODED_RUSTFLAGS").unwrap_or_default();
    let raw = env::var("RUSTFLAGS").unwrap_or_default();
    let flags = if encoded.is_empty() { raw } else { encoded };

    if !flags.contains("reqwest_unstable") {
        println!("cargo:warning=HTTP/3 requires RUSTFLAGS='--cfg reqwest_unstable'. Set in .cargo/config.toml, but a shell RUSTFLAGS env var will override it. Run: export RUSTFLAGS='--cfg reqwest_unstable'");
    }
}
