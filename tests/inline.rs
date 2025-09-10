use std::{collections::HashSet, env, ffi::OsStr, fs, path::{Path, PathBuf}, process::Command};

use bpf_linker::{Linker, LinkerInput, LinkerOptions};

fn find_binary(binary_re_str: &str) -> PathBuf {
    let binary_re = regex::Regex::new(binary_re_str).unwrap();
    let mut binary = which::which_re(binary_re).expect(binary_re_str);
    binary
        .next()
        .unwrap_or_else(|| panic!("could not find {binary_re_str}"))
}

/// Builds LLVM bitcode files from LLVM IR files located in a specified directory.
fn build_bitcode<P>(src_dir: P, dst_dir: P)
where
    P: AsRef<Path>,
{
    fs::create_dir_all(dst_dir.as_ref()).expect("failed to create a build directory for bitcode");
    for entry in fs::read_dir(src_dir.as_ref()).expect("failed to read the directory") {
        let entry = entry.expect("failed to read the entry");
        let path = entry.path();

        if path.is_file() && path.extension() == Some(OsStr::new("c")) {
            let bc_dst = dst_dir
                .as_ref()
                .join(path.with_extension("bc").file_name().unwrap());
            clang_build(path, bc_dst);
        }
    }
}

/// Compiles C code into an LLVM bitcode file.
fn clang_build<P>(src: P, dst: P)
where
    P: AsRef<Path>,
{
    let clang = find_binary(r"^clang(-\d+)?$");
    let output = Command::new(clang)
        .arg("-target")
        .arg("bpf")
        .arg("-g")
        .arg("-c")
        .arg("-emit-llvm")
        .arg("-o")
        .arg(dst.as_ref())
        .arg(src.as_ref())
        .output()
        .expect("failed to execute clang");

    if !output.status.success() {
        panic!(
            "clang failed with code {:?}\nstdout: {}\nstderr: {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}


#[test]
fn inline_test() {
    let root_dir = env::var_os("CARGO_MANIFEST_DIR")
        .expect("could not determine the root directory of the project");
    let root_dir = Path::new(&root_dir);
    let dst_dir = root_dir.join("target/inline-bitcode");
    build_bitcode(&root_dir.join("tests/inline"), &dst_dir);

    let mut files = Vec::new();
    for entry in fs::read_dir(dst_dir).expect("failed to read the directory") {
        let entry = entry.expect("failed to read the entry");
        let path = entry.path();

        files.push(path);
        // println!("{}", path.display());
    }

    let linker = Linker::new(LinkerOptions {
        target: None,
        cpu: bpf_linker::Cpu::Generic,
        cpu_features: "".to_string(),
        optimize: bpf_linker::OptLevel::Default,
        unroll_loops: false,
        ignore_inline_never: true,
        llvm_args: vec![],
        disable_expand_memcpy_in_order: false,
        disable_memory_builtins: false,
        btf: true,
        allow_bpf_trap: false,
    })
    .unwrap();

    let inputs = files.iter().map(|path| LinkerInput::new_from_file(path));

    let _linked = linker
        .link_to_buffer(
            inputs,
            bpf_linker::OutputType::Object,
            &HashSet::new(),
            None,
        )
        .unwrap();
}
