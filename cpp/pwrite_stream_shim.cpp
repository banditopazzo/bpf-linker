#include <cstdint>
#include <cstddef>
#include <cstring>

#include "llvm-c/TargetMachine.h"

#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Target/TargetMachine.h"

namespace {

using rust_write_cb  = int (*)(const uint8_t* data, size_t len, void* user);
using rust_pwrite_cb = int (*)(const uint8_t* data, size_t len, uint64_t offset, void* user);
using rust_seek_cb   = int (*)(uint64_t offset, void* user);
using rust_flush_cb  = int (*)(void* user);

// A raw_pwrite_stream that forwards write/pwrite/flush to Rust callbacks.
// - write_impl appends at the current end (updates position).
// - pwrite_impl writes at a given offset (does not change append position).
// - current_pos returns the tracked append position.
// - Optionally invokes a Rust flush callback on destruction.
class RustPwriteStream final : public llvm::raw_pwrite_stream {
public:
    RustPwriteStream(rust_write_cb wcb,
                     rust_pwrite_cb pwcb,
                     rust_seek_cb scb,
                     rust_flush_cb fcb,
                     void* user) noexcept
        : write_cb_(wcb),
          pwrite_cb_(pwcb),
          seek_cb_(scb),
          flush_cb_(fcb),
          user_(user) {
        // Disable llvm::raw_ostream internal buffering so data is forwarded immediately.
        SetUnbuffered();
    }

    ~RustPwriteStream() override {
        // Best-effort flush to the Rust sink if provided
        if (!had_error_ && flush_cb_) {
            if (flush_cb_(user_) != 0) {
                had_error_ = true;
            }
        }
    }

    // Optional: allow caller to set the logical append position and forward a seek to sink
    // (Not used by LLVM itself, but can be useful if you want to reposition the target sink.)
    bool seek_append_pos(uint64_t new_pos) {
        pos_ = new_pos;
        if (seek_cb_) {
            return seek_cb_(new_pos, user_) == 0;
        }
        return true;
    }

    bool had_error() const noexcept { return had_error_; }

private:
    void write_impl(const char* Ptr, size_t Size) override {
        if (had_error_ || Size == 0) return;
        if (!write_cb_) { had_error_ = true; return; }
        const auto rc = write_cb_(reinterpret_cast<const uint8_t*>(Ptr), Size, user_);
        if (rc != 0) {
            had_error_ = true;
            return;
        }
        // Track the new append position (raw_ostream does not track it for derived classes).
        pos_ += static_cast<uint64_t>(Size);
    }

    void pwrite_impl(const char* Ptr, size_t Size, uint64_t Offset) override {
        if (had_error_ || Size == 0) return;
        if (!pwrite_cb_) { had_error_ = true; return; }
        const auto rc = pwrite_cb_(reinterpret_cast<const uint8_t*>(Ptr), Size, Offset, user_);
        if (rc != 0) {
            had_error_ = true;
            return;
        }
        // Note: pwrite does not change append position.
    }

    uint64_t current_pos() const override {
        return pos_;
    }

private:
    rust_write_cb  write_cb_{nullptr};
    rust_pwrite_cb pwrite_cb_{nullptr};
    rust_seek_cb   seek_cb_{nullptr};
    rust_flush_cb  flush_cb_{nullptr};
    void* user_{nullptr};

    uint64_t pos_{0};
    bool had_error_{false};
};

// Small helper to strdup a C++ string safely for C API consumers.
static char* dup_cstr(const char* s) {
    if (!s) return nullptr;
    const size_t n = std::strlen(s);
    char* out = static_cast<char*>(std::malloc(n + 1));
    if (!out) return nullptr;
    std::memcpy(out, s, n);
    out[n] = '\0';
    return out;
}

// Unwrap C handles to C++ objects (mirroring TargetMachineC.cpp).
static inline llvm::TargetMachine* unwrap(LLVMTargetMachineRef T) {
    return reinterpret_cast<llvm::TargetMachine*>(T);
}
static inline llvm::Module* unwrap(LLVMModuleRef M) {
    return reinterpret_cast<llvm::Module*>(M);
}

} // namespace

extern "C" {

/// Emit object/asm to a Rust-provided random-access sink via callbacks.
/// Returns 0 on success, non-zero on error. On error, error_message (if non-null) is set to a newly allocated C string.
///
/// Required callbacks:
/// - write_cb:  append write (may be called frequently)
/// - pwrite_cb: random-access write at an absolute offset (required by LLVM for fixups)
/// Optional callbacks:
/// - seek_cb:   if provided, will be called when the shim's append position is explicitly adjusted (not used by LLVM)
/// - flush_cb:  called at the end to flush the sink
///
/// Safety/contract for the Rust sink:
/// - Must maintain a growable, contiguous byte store (like a Vec<u8> or file) so that pwrite at arbitrary offsets succeeds.
/// - pwrite must grow and zero-fill gaps if offset+len exceeds current size.
/// - write must append at the current end.
/// - flush must commit the store as needed.
///
/// Note: This function mirrors the behavior of LLVMTargetMachineEmitToFile, but uses a custom raw_pwrite_stream.
int bpf_linker_emit_to_pwrite_stream(
    LLVMTargetMachineRef T,
    LLVMModuleRef M,
    LLVMCodeGenFileType codegen,
    rust_write_cb write_cb,
    rust_pwrite_cb pwrite_cb,
    rust_seek_cb seek_cb,
    rust_flush_cb flush_cb,
    void* user,
    char** error_message // optional
) {
    if (error_message) *error_message = nullptr;

    llvm::TargetMachine* TM = unwrap(T);
    llvm::Module* Mod = unwrap(M);
    if (!TM || !Mod || !write_cb || !pwrite_cb) {
        if (error_message) *error_message = dup_cstr("invalid arguments: TM/Mod/write_cb/pwrite_cb must be non-null");
        return 1;
    }

    RustPwriteStream os(write_cb, pwrite_cb, seek_cb, flush_cb, user);

    // Set the module data layout to match the target machine (same as LLVMTargetMachineEmitToFile).
    Mod->setDataLayout(TM->createDataLayout());

    // Select file type
    llvm::CodeGenFileType ft = llvm::CodeGenFileType::ObjectFile;
    switch (codegen) {
        case LLVMAssemblyFile:
            ft = llvm::CodeGenFileType::AssemblyFile;
            break;
        default:
            ft = llvm::CodeGenFileType::ObjectFile;
            break;
    }

    // Build and run the pass pipeline
    llvm::legacy::PassManager pass;

    if (TM->addPassesToEmitFile(pass, os, nullptr, ft)) {
        if (error_message) *error_message = dup_cstr("TargetMachine can't emit a file of this type");
        return 1;
    }

    // Run codegen
    pass.run(*Mod);

    // Flush LLVM stream (no-op with SetUnbuffered, but keep it for completeness).
    os.flush();

    if (os.had_error()) {
        if (error_message) *error_message = dup_cstr("error while writing to Rust pwrite stream");
        return 1;
    }

    return 0;
}

} // extern "C"
