#include <cstddef>
#include <cstdint>

#include "llvm/Bitcode/BitcodeWriter.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/raw_ostream.h"

using rust_write_cb = int (*)(const uint8_t *data, size_t len, void *user);
using rust_flush_cb = int (*)(void *user);

namespace {

/// A minimal raw_ostream that forwards writes to Rust callbacks.
/// This stream is forward-only (no pwrite) and is suitable for streaming
/// bitcode and textual LLVM IR without intermediate memory buffers.
class RustRawOStream final : public llvm::raw_ostream {
public:
  RustRawOStream(rust_write_cb write_cb, rust_flush_cb flush_cb,
                 void *user) noexcept
      : write_cb_(write_cb), flush_cb_(flush_cb), user_(user) {
    // Disable internal buffering so we forward data immediately.
    SetUnbuffered();
  }

  ~RustRawOStream() override {
    // Flush raw_ostream buffers first.
    this->flush();
    // Then ask the Rust sink to flush, if provided.
    if (!had_error_ && flush_cb_) {
      if (flush_cb_(user_) != 0) {
        had_error_ = true;
      }
    }
  }

  bool had_error() const noexcept { return had_error_; }

private:
  void write_impl(const char *Ptr, size_t Size) override {
    if (had_error_ || Size == 0) {
      return;
    }
    if (!write_cb_) {
      had_error_ = true;
      return;
    }
    const auto rc =
        write_cb_(reinterpret_cast<const uint8_t *>(Ptr), Size, user_);
    if (rc != 0) {
      had_error_ = true;
      return;
    }
    // Track stream position (raw_ostream relies on current_pos()).
    pos_ += static_cast<uint64_t>(Size);
  }

  uint64_t current_pos() const override { return pos_; }

private:
  rust_write_cb write_cb_{nullptr};
  rust_flush_cb flush_cb_{nullptr};
  void *user_{nullptr};

  uint64_t pos_{0};
  bool had_error_{false};
};

static inline llvm::Module *unwrap(LLVMModuleRef M) {
  return reinterpret_cast<llvm::Module *>(M);
}

} // namespace

extern "C" {

/// Stream bitcode for the given module to a Rust Write sink via callbacks.
/// Returns 0 on success, non-zero on failure.
int bpf_linker_write_bitcode_to_stream(LLVMModuleRef M, rust_write_cb write_cb,
                                       rust_flush_cb flush_cb, void *user) {
  llvm::Module *Mod = unwrap(M);
  if (!Mod || !write_cb) {
    return 1;
  }

  RustRawOStream os(write_cb, flush_cb, user);
  // This writes bitcode into our RustRawOStream in chunks.
  llvm::WriteBitcodeToFile(*Mod, os);
  // raw_ostream is unbuffered, but flush anyway for completeness.
  os.flush();
  return os.had_error() ? 1 : 0;
}

/// Stream textual LLVM IR for the given module to a Rust Write sink via
/// callbacks. Returns 0 on success, non-zero on failure.
int bpf_linker_print_ir_to_stream(LLVMModuleRef M, rust_write_cb write_cb,
                                  rust_flush_cb flush_cb, void *user) {
  llvm::Module *Mod = unwrap(M);
  if (!Mod || !write_cb) {
    return 1;
  }

  RustRawOStream os(write_cb, flush_cb, user);
  // Print the IR to our stream (no analysis/AAW provided).
  Mod->print(os, /*AAW=*/nullptr);
  os.flush();
  return os.had_error() ? 1 : 0;
}

} // extern "C"
