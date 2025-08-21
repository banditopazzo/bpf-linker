use std::ffi::CStr;

use llvm_sys::target_machine::{
    LLVMCodeGenFileType, LLVMDisposeTargetMachine, LLVMTargetMachineEmitToFile,
    LLVMTargetMachineEmitToMemoryBuffer, LLVMTargetMachineRef,
};

use crate::llvm::{LLVMModuleWrapped, MemoryBufferWrapped, Message};

pub struct LLVMTargetMachineWrapped {
    pub(super) target_machine: LLVMTargetMachineRef,
}

impl LLVMTargetMachineWrapped {
    pub unsafe fn codegen_to_file(
        &self,
        module: &LLVMModuleWrapped,
        output: &CStr,
        output_type: LLVMCodeGenFileType,
    ) -> Result<(), String> {
        let (ret, message) = Message::with(|message| {
            LLVMTargetMachineEmitToFile(
                self.target_machine,
                module.module,
                output.as_ptr() as *mut _,
                output_type,
                message,
            )
        });
        if ret == 0 {
            Ok(())
        } else {
            Err(message.as_c_str().unwrap().to_str().unwrap().to_string())
        }
    }

    pub unsafe fn codegen_to_mem(
        &self,
        module: &LLVMModuleWrapped,
        output_type: LLVMCodeGenFileType,
    ) -> Result<MemoryBufferWrapped, String> {
        let mut out_buf = std::ptr::null_mut();
        let (ret, message) = Message::with(|message| {
            LLVMTargetMachineEmitToMemoryBuffer(
                self.target_machine,
                module.module,
                output_type,
                message,
                &mut out_buf,
            )
        });
        if ret != 0 {
            return Err(message.as_c_str().unwrap().to_str().unwrap().to_string());
        }

        Ok(MemoryBufferWrapped {
            memory_buffer: out_buf,
        })
    }

    #[cfg(feature = "stream-io")]
    pub unsafe fn codegen_to_writer(
        &self,
        module: &LLVMModuleWrapped,
        output_type: LLVMCodeGenFileType,
        writer: &mut (impl std::io::Write + std::io::Seek),
    ) -> Result<(), String> {
        use crate::llvm::pwrite_stream::{
            bpf_linker_emit_to_pwrite_stream, rust_shim_flush_cb, rust_shim_pwrite_cb,
            rust_shim_seek_cb, rust_shim_write_cb, PwriteSink, WriteSeek,
        };
        let trait_obj: &mut dyn WriteSeek = writer;
        let mut sink = PwriteSink::new(trait_obj).map_err(|e| e.to_string())?;

        let mut err_ptr: *mut std::os::raw::c_char = std::ptr::null_mut();
        let ret = bpf_linker_emit_to_pwrite_stream(
            self.target_machine,
            module.module,
            output_type,
            rust_shim_write_cb,
            rust_shim_pwrite_cb,
            Some(rust_shim_seek_cb),
            Some(rust_shim_flush_cb),
            (&mut sink as *mut PwriteSink) as *mut std::os::raw::c_void,
            &mut err_ptr,
        );
        if ret != 0 {
            let msg = if err_ptr.is_null() {
                "error while writing to pwrite stream".to_string()
            } else {
                let cstr = std::ffi::CStr::from_ptr(err_ptr);
                let s = cstr.to_string_lossy().into_owned();
                unsafe { libc::free(err_ptr as *mut libc::c_void) };
                s
            };
            return Err(msg);
        }

        Ok(())
    }
}

impl Drop for LLVMTargetMachineWrapped {
    fn drop(&mut self) {
        unsafe {
            LLVMDisposeTargetMachine(self.target_machine);
        }
    }
}
