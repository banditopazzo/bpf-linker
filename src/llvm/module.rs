use std::{
    ffi::{CStr, CString},
    marker::PhantomData,
};
#[cfg(feature = "stream-io")]
use std::{io::Write, os::raw::{c_int, c_uchar, c_void}};

use llvm_sys::{
    bit_writer::LLVMWriteBitcodeToFile,
    core::{
        LLVMCreateMemoryBufferWithMemoryRangeCopy, LLVMDisposeMessage, LLVMDisposeModule,
        LLVMGetTarget, LLVMPrintModuleToFile, LLVMPrintModuleToString,
    },
    prelude::LLVMModuleRef,
};

#[cfg(feature = "stream-io")]
extern "C" {
    fn bpf_linker_write_bitcode_to_stream(
        module: LLVMModuleRef,
        write_cb: extern "C" fn(*const c_uchar, usize, *mut c_void) -> c_int,
        flush_cb: extern "C" fn(*mut c_void) -> c_int,
        user: *mut c_void,
    ) -> c_int;

    fn bpf_linker_print_ir_to_stream(
        module: LLVMModuleRef,
        write_cb: extern "C" fn(*const c_uchar, usize, *mut c_void) -> c_int,
        flush_cb: extern "C" fn(*mut c_void) -> c_int,
        user: *mut c_void,
    ) -> c_int;
}

use crate::llvm::{MemoryBufferWrapped, Message};

pub struct LLVMModuleWrapped<'ctx> {
    pub(super) module: LLVMModuleRef,
    pub(super) _marker: PhantomData<&'ctx super::LLVMContextWrapped>,
}

impl<'ctx> LLVMModuleWrapped<'ctx> {
    pub unsafe fn get_target(&self) -> *const i8 {
        unsafe { LLVMGetTarget(self.module) }
    }

    pub fn write_bitcode_to_file(&self, output: &CStr) -> Result<(), String> {
        if unsafe { LLVMWriteBitcodeToFile(self.module, output.as_ptr()) } == 1 {
            return Err("failed to write bitcode".to_string());
        }

        Ok(())
    }

    pub unsafe fn write_bitcode_to_memory(&self) -> MemoryBufferWrapped {
        let buf = llvm_sys::bit_writer::LLVMWriteBitcodeToMemoryBuffer(self.module);

        MemoryBufferWrapped { memory_buffer: buf }
    }

    pub unsafe fn write_ir_to_file(&self, output: &CStr) -> Result<(), String> {
        let (ret, message) =
            Message::with(|message| LLVMPrintModuleToFile(self.module, output.as_ptr(), message));
        if ret == 0 {
            Ok(())
        } else {
            Err(message.as_c_str().unwrap().to_str().unwrap().to_string())
        }
    }

    pub unsafe fn write_ir_to_memory(&self) -> MemoryBufferWrapped {
        let ptr = LLVMPrintModuleToString(self.module);
        let cstr = CStr::from_ptr(ptr);
        let bytes = cstr.to_bytes();

        let buffer_name = CString::new("mem_buffer").unwrap();

        // Copy bytes into a new LLVMMemoryBuffer so we can safely dispose the message.
        let memory_buffer = LLVMCreateMemoryBufferWithMemoryRangeCopy(
            bytes.as_ptr() as *const ::libc::c_char,
            bytes.len(),
            buffer_name.as_ptr(),
        );
        LLVMDisposeMessage(ptr);

        MemoryBufferWrapped { memory_buffer }
    }

    #[cfg(feature = "stream-io")]
    pub unsafe fn stream_bitcode_to_writer(
        &self,
        mut writer: impl Write,
    ) -> std::io::Result<()> {
        #[repr(C)]
        struct Sink<'a> {
            w: &'a mut dyn Write,
        }

        extern "C" fn write_cb(ptr: *const c_uchar, len: usize, user: *mut c_void) -> c_int {
            let sink = unsafe { &mut *(user as *mut Sink) };
            let buf = unsafe { std::slice::from_raw_parts(ptr, len) };
            match sink.w.write_all(buf) {
                Ok(_) => 0,
                Err(_) => 1,
            }
        }

        extern "C" fn flush_cb(user: *mut c_void) -> c_int {
            let sink = unsafe { &mut *(user as *mut Sink) };
            match sink.w.flush() {
                Ok(_) => 0,
                Err(_) => 1,
            }
        }

        let mut sink = Sink { w: &mut writer };
        let rc = bpf_linker_write_bitcode_to_stream(
            self.module,
            write_cb,
            flush_cb,
            (&mut sink as *mut Sink) as *mut c_void,
        );
        if rc == 0 {
            Ok(())
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "bitcode streaming failed",
            ))
        }
    }

    #[cfg(feature = "stream-io")]
    pub unsafe fn stream_ir_to_writer(
        &self,
        mut writer: impl Write,
    ) -> std::io::Result<()> {
        #[repr(C)]
        struct Sink<'a> {
            w: &'a mut dyn Write,
        }

        extern "C" fn write_cb(ptr: *const c_uchar, len: usize, user: *mut c_void) -> c_int {
            let sink = unsafe { &mut *(user as *mut Sink) };
            let buf = unsafe { std::slice::from_raw_parts(ptr, len) };
            match sink.w.write_all(buf) {
                Ok(_) => 0,
                Err(_) => 1,
            }
        }

        extern "C" fn flush_cb(user: *mut c_void) -> c_int {
            let sink = unsafe { &mut *(user as *mut Sink) };
            match sink.w.flush() {
                Ok(_) => 0,
                Err(_) => 1,
            }
        }

        let mut sink = Sink { w: &mut writer };
        let rc = bpf_linker_print_ir_to_stream(
            self.module,
            write_cb,
            flush_cb,
            (&mut sink as *mut Sink) as *mut c_void,
        );
        if rc == 0 {
            Ok(())
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "IR streaming failed",
            ))
        }
    }
}

impl<'ctx> Drop for LLVMModuleWrapped<'ctx> {
    fn drop(&mut self) {
        unsafe { LLVMDisposeModule(self.module) };
    }
}
