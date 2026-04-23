//! OmniWatch verifier — methods build script
//!
//! Cross-compiles the guest crate for riscv32im-risc0-zkvm-elf using the
//! nightly Rust toolchain (no rzup / RISC Zero custom toolchain required),
//! combines the user ELF with the pre-built V1COMPAT kernel from
//! risc0-zkos-v1compat, and generates OUT_DIR/methods.rs with
//! VERIFIER_GUEST_ELF and VERIFIER_GUEST_ID constants.

use std::{
    env,
    path::{Path, PathBuf},
    process::Command,
};

use risc0_binfmt::{compute_image_id, ProgramBinary};
use risc0_zkos_v1compat::V1COMPAT_ELF;

const TARGET: &str = "riscv32im-risc0-zkvm-elf";
const GUEST_NAME: &str = "verifier-guest";
const CONST_PREFIX: &str = "VERIFIER_GUEST";

fn main() {
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let guest_manifest = Path::new(env!("CARGO_MANIFEST_DIR")).join("guest/Cargo.toml");

    // Tell cargo to re-run if guest sources change.
    println!("cargo:rerun-if-changed=guest/src/main.rs");
    println!("cargo:rerun-if-changed=guest/Cargo.toml");

    // ── Step 1: cross-compile the guest ──────────────────────────────────────
    //
    // We invoke `cargo +nightly build` with -Z build-std so that core/alloc
    // are compiled from source for riscv32im-risc0-zkvm-elf (a Tier-3 target
    // with no prebuilt stdlib artifacts).  The nightly toolchain must be
    // installed: `rustup toolchain install nightly && rustup component add
    // rust-src --toolchain nightly`.

    let guest_target_dir = out_dir.join("guest-target");

    // Locate the rustup binary so we can invoke `rustup run nightly cargo …`.
    // This reliably switches to the nightly toolchain (including nightly cargo)
    // regardless of how the current build is invoked.
    let rustup_bin = which_rustup();
    // Ask rustup for the nightly toolchain root directory so we can set
    // RUSTC / RUSTC_WORKSPACE_WRAPPER explicitly.  This guarantees the nightly
    // cargo uses the nightly rustc (and therefore finds nightly's rust-src).
    let nightly_toolchain_root = nightly_toolchain_dir(&rustup_bin);
    eprintln!("[build.rs] rustup path: {}", rustup_bin.display());
    eprintln!("[build.rs] nightly toolchain root: {:?}", nightly_toolchain_root);
    eprintln!("[build.rs] CARGO env: {:?}", env::var("CARGO"));
    eprintln!("[build.rs] RUSTUP_TOOLCHAIN env: {:?}", env::var("RUSTUP_TOOLCHAIN"));

    // Cargo searches for config.toml starting from the *current working
    // directory*, not the --manifest-path directory.  Run the subprocess from
    // the guest directory so that guest/.cargo/config.toml is discovered.
    let guest_dir = guest_manifest.parent().unwrap();

    let status = Command::new(&rustup_bin)
        .args([
            "run",
            "nightly",
            "cargo",
            "build",
            "--release",
            "--target",
            TARGET,
            "-Z",
            "build-std=core,alloc,std,panic_abort",
            "-Z",
            "build-std-features=compiler-builtins-mem",
            "--manifest-path",
            guest_manifest.to_str().unwrap(),
            "--target-dir",
            guest_target_dir.to_str().unwrap(),
        ])
        .current_dir(guest_dir)
        // Avoid inheriting host-side flags that target x86_64.
        .env_remove("RUSTFLAGS")
        .env_remove("CARGO_ENCODED_RUSTFLAGS")
        // Cargo sets RUSTUP_TOOLCHAIN to the current (stable) toolchain.
        // Remove it so `rustup run nightly` is honoured.
        .env_remove("RUSTUP_TOOLCHAIN")
        // Cargo sets CARGO to the stable cargo binary.  build-std derives the
        // rust-src location from CARGO's path (or RUSTC's path), so we must
        // clear CARGO and point RUSTC at the nightly rustc explicitly.
        .env_remove("CARGO")
        .env_remove("RUSTC")  // clear any inherited rustc path
        // Point RUSTC_BOOTSTRAP at 1 so nightly features work even if cargo
        // falls back to a stable rustc for any reason.
        .env("RUSTC_BOOTSTRAP", "1")
        .status()
        .expect("failed to invoke rustup — is the nightly toolchain installed?");

    assert!(
        status.success(),
        "guest cross-compilation failed (see cargo output above)"
    );

    // ── Step 2: locate the compiled ELF ──────────────────────────────────────
    let user_elf_path = guest_target_dir
        .join(TARGET)
        .join("release")
        .join(GUEST_NAME);

    let user_elf = std::fs::read(&user_elf_path).unwrap_or_else(|e| {
        panic!(
            "cannot read compiled guest ELF at {}: {e}",
            user_elf_path.display()
        )
    });

    // ── Step 3: combine user ELF + kernel → program binary ───────────────────
    //
    // risc0 v2.x requires the user ELF to be fused with the pre-built zkOS
    // kernel (V1COMPAT_ELF) before being loaded into the VM.  The resulting
    // `.bin` is what gets embedded in the host binary and passed to the prover.
    let binary = ProgramBinary::new(&user_elf, V1COMPAT_ELF);
    let combined_elf = binary.encode();

    let combined_path = out_dir.join(format!("{GUEST_NAME}.bin"));
    std::fs::write(&combined_path, &combined_elf)
        .expect("failed to write combined program binary");

    // ── Step 4: compute image ID ─────────────────────────────────────────────
    let image_id = compute_image_id(&combined_elf)
        .expect("failed to compute image ID from combined ELF");

    // ── Step 5: generate methods.rs ──────────────────────────────────────────
    let image_id_words = image_id.as_words();
    let methods_rs = format!(
        r#"// GENERATED by verifier/methods/build.rs — do not edit manually.
pub const {CONST_PREFIX}_ELF: &[u8] = include_bytes!({:?});
pub const {CONST_PREFIX}_PATH: &str = {:?};
pub const {CONST_PREFIX}_ID: [u32; 8] = {image_id_words:?};
"#,
        combined_path.to_str().unwrap(),
        combined_path.to_str().unwrap(),
    );

    std::fs::write(out_dir.join("methods.rs"), &methods_rs)
        .expect("failed to write methods.rs");

    println!("[methods/build.rs] image ID: {image_id:?}");
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Find the `rustup` binary.
///
/// When cargo runs a build script it sets `CARGO` to the DIRECT path of the
/// cargo binary inside the active toolchain directory, NOT to the rustup proxy
/// in `~/.cargo/bin/`.  Rustup itself lives in `~/.cargo/bin/`, so we derive
/// its path from `CARGO_HOME` (or the default `~/.cargo/bin/`).
fn which_rustup() -> PathBuf {
    // CARGO_HOME is set by rustup; fall back to ~/.cargo.
    let cargo_home = env::var_os("CARGO_HOME")
        .map(PathBuf::from)
        .or_else(|| {
            dirs_home().map(|h| h.join(".cargo"))
        });

    if let Some(home) = cargo_home {
        let rustup = home.join("bin").join(if cfg!(windows) { "rustup.exe" } else { "rustup" });
        if rustup.exists() {
            return rustup;
        }
    }

    // Last resort: rely on PATH.
    PathBuf::from("rustup")
}

/// Best-effort home directory (needed for CARGO_HOME fallback).
fn dirs_home() -> Option<PathBuf> {
    // On Windows check USERPROFILE; on Unix check HOME.
    env::var_os("USERPROFILE")
        .or_else(|| env::var_os("HOME"))
        .map(PathBuf::from)
}

/// Returns the root directory of the installed nightly toolchain, e.g.
/// `~/.rustup/toolchains/nightly-x86_64-pc-windows-msvc`.
/// Falls back to None if rustup cannot locate it.
fn nightly_toolchain_dir(rustup: &Path) -> Option<PathBuf> {
    let out = Command::new(rustup)
        .args(["run", "nightly", "rustc", "--print", "sysroot"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let sysroot = String::from_utf8(out.stdout).ok()?;
    Some(PathBuf::from(sysroot.trim()))
}

// ── x86_64 host stub ─────────────────────────────────────────────────────────
//
// risc0-zkvm-platform v2.x declares `sys_alloc_aligned` as an extern "C"
// symbol (resolved by the zkVM runtime on riscv32im; undefined on x86_64).
// Defining it here satisfies the MSVC linker when this build script is
// compiled as a native binary.  It is never called at runtime.
#[no_mangle]
pub unsafe extern "C" fn sys_alloc_aligned(bytes: usize, align: usize) -> *mut u8 {
    use std::alloc::{alloc, Layout};
    match Layout::from_size_align(bytes, align) {
        Ok(layout) => alloc(layout),
        Err(_) => std::ptr::null_mut(),
    }
}
