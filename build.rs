use std::env;
use std::process::Command;

fn main() {
    // Always track changes for both shims so cargo can rebuild when features toggle.
    println!("cargo:rerun-if-changed=cpp/pwrite_stream_shim.cpp");
    println!("cargo:rerun-if-changed=cpp/bitcode_ir_stream_shim.cpp");

    // Build both shims when unified feature is enabled.
    if env::var_os("CARGO_FEATURE_STREAM_IO").is_some() {
        // pwrite stream shim (object/asm)
        let mut build = cc::Build::new();
        build.cpp(true);
        build.file("cpp/pwrite_stream_shim.cpp");
        build.flag_if_supported("-std=c++17");
        build.flag_if_supported("/std:c++17");
        build.warnings(false);

        if let Some(cfg) = probe_llvm_config() {
            apply_llvm_cxxflags(&mut build, &cfg);
        } else {
            println!("cargo:warning=stream-io enabled but llvm-config not found; attempting minimal compile (pwrite shim)");
        }

        build.compile("pwrite_stream_shim");
        link_cxx_standard_library();

        // bitcode/IR forward-only stream shim
        let mut build2 = cc::Build::new();
        build2.cpp(true);
        build2.file("cpp/bitcode_ir_stream_shim.cpp");
        build2.flag_if_supported("-std=c++17");
        build2.flag_if_supported("/std:c++17");
        build2.warnings(false);

        if let Some(cfg) = probe_llvm_config() {
            apply_llvm_cxxflags(&mut build2, &cfg);
        } else {
            println!("cargo:warning=stream-io enabled but llvm-config not found; attempting minimal compile (bitcode/ir shim)");
        }

        build2.compile("bitcode_ir_stream_shim");
        link_cxx_standard_library();
    }
}

fn probe_llvm_config() -> Option<String> {
    let llvm_config = env::var("LLVM_CONFIG_PATH").unwrap_or_else(|_| "llvm-config".to_string());
    match Command::new(&llvm_config).arg("--cxxflags").output() {
        Ok(out) if out.status.success() => {
            let s = String::from_utf8_lossy(&out.stdout).to_string();
            Some(s)
        }
        _ => None,
    }
}

fn apply_llvm_cxxflags(build: &mut cc::Build, flags: &str) {
    for token in shell_split(flags).into_iter() {
        if let Some(path) = token.strip_prefix("-I") {
            if !path.is_empty() {
                build.include(path);
            }
            continue;
        }
        if let Some(def) = token.strip_prefix("-D") {
            if !def.is_empty() {
                if let Some((k, v)) = def.split_once('=') {
                    build.define(k, Some(v));
                } else {
                    build.define(def, None);
                }
            }
            continue;
        }

        match token.as_str() {
            "-fPIC" | "-fPIE" | "-fno-exceptions" | "-fno-rtti" | "-Wno-unused-parameter"
            | "-Wno-missing-field-initializers" | "-Wno-comment" | "-Wno-deprecated-declarations" => {
                build.flag(token);
            }
            t if t.starts_with("-std=") || t.eq_ignore_ascii_case("/std:c++17") => {}
            t if cfg!(target_env = "msvc") && (t.starts_with("/Zc:") || t.starts_with("/MD")) => {
                build.flag(token);
            }
            _ => {}
        }
    }
}

fn shell_split(s: &str) -> Vec<String> {
    s.split_whitespace().map(|t| t.to_string()).collect()
}

fn link_cxx_standard_library() {
    let target = env::var("TARGET").unwrap_or_default();

    if target.contains("apple-darwin") {
        println!("cargo:rustc-link-lib=dylib=c++");
    } else if target.contains("windows-msvc") {
        // MSVC links the C++ stdlib implicitly; nothing to do.
    } else if target.contains("windows-gnu") {
        println!("cargo:rustc-link-lib=dylib=stdc++");
    } else if target.contains("android") {
        println!("cargo:rustc-link-lib=dylib=c++_shared");
    } else {
        println!("cargo:rustc-link-lib=dylib=stdc++");
    }
}
