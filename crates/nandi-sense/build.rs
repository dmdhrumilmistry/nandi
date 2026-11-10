//! Compiles the eBPF program when the `ebpf` feature is enabled on Linux.
//!
//! Without the feature this does nothing, so default builds never need
//! clang. With it, `clang` (or the compiler named by `CLANG`) must target
//! BPF and find `<linux/bpf.h>` and `<bpf/bpf_helpers.h>` (Debian/Ubuntu:
//! `clang llvm libbpf-dev`). `NANDI_BPF_CFLAGS` adds extra flags.

use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

const SOURCE: &str = "bpf/sense.bpf.c";

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed={SOURCE}");
    println!("cargo:rerun-if-env-changed=CLANG");
    println!("cargo:rerun-if-env-changed=NANDI_BPF_CFLAGS");
    let ebpf = env::var_os("CARGO_FEATURE_EBPF").is_some();
    let linux = env::var("CARGO_CFG_TARGET_OS").is_ok_and(|os| os == "linux");
    if !(ebpf && linux) {
        return;
    }
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR")).join("sense.bpf.o");
    let clang = env::var("CLANG").unwrap_or_else(|_| "clang".into());
    let target = if env::var("CARGO_CFG_TARGET_ENDIAN").is_ok_and(|e| e == "big") { "bpfeb" } else { "bpfel" };

    // Syscall numbers and argument registers differ per architecture.
    let arch = match env::var("CARGO_CFG_TARGET_ARCH").as_deref() {
        Ok("x86_64") => "x86",
        Ok("aarch64") => "arm64",
        other => panic!("the `ebpf` feature supports x86_64 and aarch64, not {other:?}"),
    };

    let mut cmd = Command::new(&clang);
    cmd.args(["-target", target, "-O2", "-g", "-Wall", "-Werror"])
        .arg(format!("-D__TARGET_ARCH_{arch}"))
        .args(["-c", SOURCE, "-o"])
        .arg(&out);
    // <linux/bpf.h> pulls in <asm/types.h>, which Debian-style systems keep
    // under a multiarch directory that a BPF-target clang does not search.
    if let Some(dir) = multiarch_include() {
        cmd.arg(format!("-I{}", dir.display()));
    }
    if let Ok(extra) = env::var("NANDI_BPF_CFLAGS") {
        cmd.args(extra.split_whitespace());
    }
    let status = match cmd.status() {
        Ok(s) => s,
        Err(e) => panic!(
            "the `ebpf` feature needs clang to compile {SOURCE} ({clang}: {e}). \
             Install clang and libbpf headers (e.g. `apt install clang llvm libbpf-dev`) \
             or point CLANG at a clang binary."
        ),
    };
    assert!(status.success(), "compiling {SOURCE} with {clang} failed ({status})");
}

fn multiarch_include() -> Option<PathBuf> {
    let arch = env::var("CARGO_CFG_TARGET_ARCH").ok()?;
    let triple = match arch.as_str() {
        "x86_64" => "x86_64-linux-gnu",
        "aarch64" => "aarch64-linux-gnu",
        _ => return None,
    };
    let dir = Path::new("/usr/include").join(triple);
    dir.join("asm/types.h").exists().then_some(dir)
}
