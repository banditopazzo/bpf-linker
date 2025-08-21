#![cfg(feature = "stream-io")]

//! pwrite_stream.rs
//!
//! Minimal Rust-side glue for emitting object/assembly directly to an arbitrary
//! Write + Seek sink using the C++ raw_pwrite_stream shim.
//!
//! This module is compiled only when the `pwrite-stream-shim` feature is
//! enabled. It provides only the bare minimum:
//! - FFI bindings to the C++ function `bpf_linker_emit_to_pwrite_stream`
//! - A lightweight, object-safe `WriteSeek` trait alias
//! - `PwriteSink` wrapper tracking the logical append position
//! - The four C callbacks required by the C++ shim (write, pwrite, seek, flush)

use std::io::{Seek, SeekFrom, Write};
use std::os::raw::{c_char, c_int, c_uchar, c_void};

use llvm_sys::prelude::LLVMModuleRef;
use llvm_sys::target_machine::{LLVMCodeGenFileType, LLVMTargetMachineRef};

// FFI binding to the C++ shim in `cpp/pwrite_stream_shim.cpp`.
//
// Returns 0 on success, non-zero on error. On error, `err` (if non-null)
// points to a newly allocated C string that must be freed with `libc::free`.
unsafe extern "C" {
    pub unsafe fn bpf_linker_emit_to_pwrite_stream(
        tm: LLVMTargetMachineRef,
        module: LLVMModuleRef,
        kind: LLVMCodeGenFileType,
        write_cb: extern "C" fn(*const c_uchar, usize, *mut c_void) -> c_int,
        pwrite_cb: extern "C" fn(*const c_uchar, usize, u64, *mut c_void) -> c_int,
        seek_cb: Option<extern "C" fn(u64, *mut c_void) -> c_int>,
        flush_cb: Option<extern "C" fn(*mut c_void) -> c_int>,
        user: *mut c_void,
        err: *mut *mut c_char,
    ) -> c_int;
}

/// Object-safe alias for a writer that can also seek.
pub trait WriteSeek: Write + Seek {}
impl<T: Write + Seek> WriteSeek for T {}

/// A sink wrapper holding a `Write + Seek` instance plus the current
/// logical append position used by LLVM's raw_ostream.
pub struct PwriteSink<'a> {
    pub writer: &'a mut dyn WriteSeek,
    pub pos: u64,
}

impl<'a> PwriteSink<'a> {
    /// Create a new sink, initializing the append position to the
    /// current position of the underlying writer.
    pub fn new(writer: &'a mut dyn WriteSeek) -> std::io::Result<Self> {
        let pos = writer.seek(SeekFrom::Current(0))?;
        Ok(Self { writer, pos })
    }
}

/// Append write callback: forwards write_impl(...) calls.
/// Advances the tracked append position on success.
#[no_mangle]
pub extern "C" fn rust_shim_write_cb(ptr: *const c_uchar, len: usize, user: *mut c_void) -> c_int {
    let sink = unsafe { &mut *(user as *mut PwriteSink) };
    let buf = unsafe { std::slice::from_raw_parts(ptr, len) };

    if sink.writer.seek(SeekFrom::Start(sink.pos)).is_err() {
        return 1;
    }
    if sink.writer.write_all(buf).is_err() {
        return 1;
    }
    sink.pos = sink.pos.saturating_add(len as u64);
    0
}

/// Random-access write callback: forwards pwrite_impl(..., offset).
/// Does not change the tracked append position, and restores the
/// file cursor to the append position after writing.
#[no_mangle]
pub extern "C" fn rust_shim_pwrite_cb(
    ptr: *const c_uchar,
    len: usize,
    offset: u64,
    user: *mut c_void,
) -> c_int {
    let sink = unsafe { &mut *(user as *mut PwriteSink) };
    let buf = unsafe { std::slice::from_raw_parts(ptr, len) };

    if sink.writer.seek(SeekFrom::Start(offset)).is_err() {
        return 1;
    }
    if sink.writer.write_all(buf).is_err() {
        return 1;
    }
    // Restore to append position so future write() appends correctly
    if sink.writer.seek(SeekFrom::Start(sink.pos)).is_err() {
        return 1;
    }
    0
}

/// Seek callback: allows explicitly adjusting the logical append position
/// and seeking the writer to the same location (not used by LLVM itself).
#[no_mangle]
pub extern "C" fn rust_shim_seek_cb(offset: u64, user: *mut c_void) -> c_int {
    let sink = unsafe { &mut *(user as *mut PwriteSink) };
    sink.pos = offset;
    match sink.writer.seek(SeekFrom::Start(offset)) {
        Ok(_) => 0,
        Err(_) => 1,
    }
}

/// Flush callback: flush the underlying writer.
#[no_mangle]
pub extern "C" fn rust_shim_flush_cb(user: *mut c_void) -> c_int {
    let sink = unsafe { &mut *(user as *mut PwriteSink) };
    match sink.writer.flush() {
        Ok(_) => 0,
        Err(_) => 1,
    }
}
