// Two address decisions that must not be re-derived per module.
//
// Both generators -- fuzzer/codegen.py's templates and fuzzer/codegen_llm.py's model --
// need them, and both got one wrong when each owned its own copy. CLAUDE.md section 14.3
// states the principle: the model fills a schema, it never writes the part where a
// mistake is silent. This is that part, as ordinary code, included by whatever writes the
// module.
//
// The failures being prevented are recorded, not hypothetical:
//
//   * ResolveModuleBase -- g_Dbg->GetModuleBase returned 0 on a real snapshot whose
//     symbol-store.json had been written by an earlier run against a DIFFERENT program.
//     The breakpoint went to 0 + rva, which is not mapped, so it never fired, and Init
//     returned true anyway. The campaign ran to completion, reported coverage, delivered
//     nothing and found nothing (D-075).
//
//   * ResolveInputAddress -- the 550B wrote `const uint64_t PageBase = Backend->Rcx();`
//     and added `kPageSize - Bytes` to it. Rcx is a POINTER, not a page base:
//     0xd3d77ff7a0 + 0xff0 is 0xd3d7800790, past the end of the page. It named the
//     variable PageBase and never masked, on two independent generations.
//
#pragma once

#include "backend.h"
#include "debugger.h"
#include <cstdint>
#include <cstdlib>
#include <fmt/format.h>

namespace snapfuzz {

constexpr uint64_t kPageSize = 0x1000;

//
// WHERE THE TARGET MODULE IS MAPPED.
//
// The name first, then SNAPFUZZ_MODULE_BASE, which fuzzer/run.py sets from A1 -- where
// the base came from walking the dump's own page tables and matching the PE header, so
// it does not depend on any name resolving. If neither works this returns 0 and the
// caller's Init MUST refuse: a harness that cannot place its breakpoint must not report
// success.
//
inline uint64_t ResolveModuleBase(const char *Name) {
  const uint64_t FromDebugger = g_Dbg->GetModuleBase(Name);
  if (FromDebugger != 0) {
    return FromDebugger;
  }

  const char *Env = std::getenv("SNAPFUZZ_MODULE_BASE");
  if (Env != nullptr && Env[0] != 0) {
    const uint64_t FromEnv = std::strtoull(Env, nullptr, 0);
    if (FromEnv != 0) {
      fmt::print("snapfuzz: GetModuleBase returned 0 for {}; using "
                 "SNAPFUZZ_MODULE_BASE={:#x}\n",
                 Name, FromEnv);
      return FromEnv;
    }
  }

  fmt::print("snapfuzz: cannot locate module {} in this snapshot.\n"
             "  GetModuleBase returned 0 and SNAPFUZZ_MODULE_BASE is unset or zero.\n"
             "  A breakpoint at 0 + rva never fires, so nothing would be delivered\n"
             "  and the campaign would report coverage while finding nothing.\n"
             "  Check state/symbol-store.json describes THIS program: wtf merges into\n"
             "  that file, so a previous target's entries can survive.\n",
             Name);
  return 0;
}

//
// WHERE THE INPUT GOES, so that overflowing it is OBSERVABLE.
//
// In a snapshot fuzzer the harness supplies the buffer, so a target that overflows the
// buffer it was handed overflows into memory WE chose. Place the input so it ends exactly
// at an unmapped page and the first byte past the end faults; that fault becomes an
// access violation, and wtf's oracle already breakpoints ntdll!RtlDispatchException and
// calls SaveCrash (src/wtf/crash_detection_umode.cc:38-110). CLAUDE.md section 2's
// mitigation (a) for one bug class, decided once before the campaign, so RULE 1 is
// untouched.
//
// It matters on a real target. The second one's planted bug is
//
//     memset(param_1, 'A', (byte)param_1[4])          // fuzzme, rva 0x10d0
//
// writing into the INPUT BUFFER -- fuzzme has no locals and no stack cookie, so nothing
// in the target can notice. Placed in a roomy scratch region a 200-byte memset is an
// in-bounds write, and reporting no crash is correct.
//
// `Bytes` is the number of bytes ACTUALLY WRITTEN, never a reported size: the guard must
// sit behind the real data, or an over-reported length reads our own bytes instead of
// faulting.
//
// With no verified boundary this falls back to the tail of the pointer's own page and
// SAYS SO, because an unverified guard page fails OPEN -- the overflow lands in the next
// mapped page, nothing faults, and "no crashes" comes to mean "no crashes were
// observable".
//
//
// RETURNS Gva_t. One type, the one every guest-memory call takes.
//
// The previous version returned a struct with implicit conversions to BOTH `uint64_t` and
// `Gva_t`, reasoning that a helper meant to remove a decision should not impose one. That
// was wrong, and measurably so: it made the natural call sites AMBIGUOUS instead of
// flexible. `Backend_t::Rcx` is overloaded on `uint64_t` and `Gva_t` (backend.h:554-555),
// so a value convertible to both gives
//
//     error C2668: 'Backend_t::Rcx': ambiguous call to overloaded function
//     error C2440: cannot convert from 'const snapfuzz::InputAddress' to 'Gva_t'
//     error C2228: left of '.U64' must have class/struct/union
//
// on one generation in three -- the model writing perfectly reasonable C++ against a type
// I had made unusable. Two implicit conversions do not widen what compiles, they delete
// overload resolution.
//
// So: `Gva_t`, which `Backend->Rcx(...)`, `VirtWriteDirty` and `SetBreakpoint` all accept
// directly, which supports `+ Gva_t(sizeof(x))`, and whose `.U64()` gives the integer when
// one is wanted. The deterministic renderer calls `.U64()` and keeps its own arithmetic.
//
inline Gva_t ResolveInputAddress(uint64_t Pointer, size_t Bytes) {
  if (Bytes == 0 || Bytes > kPageSize) {
    return Gva_t(Pointer);
  }

  //
  // WHEN THE TARGET OWNS THE BUFFER, WRITE AT THE POINTER. Checked FIRST, because both the
  // guard boundary and the page-tail fallback are relocations, and relocating into a
  // buffer the target sized is wrong in the same way for both.
  //
  // HarnessSpec.input_buffer_bytes is what the target provides. On the second real target
  // it is 32: `FUN_1400011a0` prepares a 32-byte stack buffer, zeroes it, and passes it to
  // `fuzzme`. A page-tail placement then writes ~4 KB above the pointer -- and since the
  // pointer is on the stack, that is 2 KB ABOVE rsp, i.e. into the frames of the callers,
  // including the one holding `__security_cookie ^ frame`.
  //
  // Measured: `__security_check_cookie` (rva 0x1210) failed and took the security-failure
  // path on EVERY input, good and overflowing alike -- 3.3k instructions, cov 3089,
  // `crash: 1`, byte-identical for both. A textbook stack-overflow signature manufactured
  // entirely by the harness (D-083).
  //
  // Writing at the pointer is also what makes the real bug findable HERE: an over-long
  // input overflows the target's own 32-byte buffer, and the target's own cookie check
  // notices. No guard page required -- the target already has one.
  //
  const char *BufEnv = std::getenv("SNAPFUZZ_INPUT_BUFFER_BYTES");
  if (BufEnv != nullptr && BufEnv[0] != 0) {
    const uint64_t BufferBytes = std::strtoull(BufEnv, nullptr, 0);
    if (BufferBytes > 0 && BufferBytes < kPageSize) {
      static bool AtPointerNoted = false;
      if (!AtPointerNoted) {
        AtPointerNoted = true;
        fmt::print("snapfuzz: the target provides {} bytes at the input pointer, so the "
                   "test-case is written AT it.\n"
                   "  No guard page is placed: relocating into a buffer the target sized "
                   "would write past it\n"
                   "  and, on a stack pointer, corrupt the caller frames.\n",
                   BufferBytes);
      }
      return Gva_t(Pointer);
    }
  }

  const char *Env = std::getenv("SNAPFUZZ_GUARD_BOUNDARY");
  if (Env != nullptr && Env[0] != 0) {
    const uint64_t Boundary = std::strtoull(Env, nullptr, 0);

    //
    // THE CAP IS NOT OPTIONAL. The boundary is the top of a page whose TRAILING bytes are
    // unused -- 1951 of them on the development snapshot, the rest holding live data. An
    // input larger than that, placed at Boundary - Bytes, would start below the slack and
    // overwrite state the target reads. The resulting fault would be the harness's, and a
    // fabricated crash is worse than the missed bug the guard page was added to find.
    //
    // So: honour the guard page up to the cap, and fall through to the page-tail
    // placement beyond it. prep/guard_page.py measures the slack and fuzzer/run.py passes
    // it; a boundary with no cap is treated as covering nothing.
    //
    const char *MaxEnv = std::getenv("SNAPFUZZ_GUARD_MAX_BYTES");
    const uint64_t Max = MaxEnv != nullptr && MaxEnv[0] != 0
                             ? std::strtoull(MaxEnv, nullptr, 0)
                             : 0;
    if (Boundary >= Bytes && Bytes <= Max) {
      return Gva_t(Boundary - Bytes);
    }

    static bool CapWarned = false;
    if (Max != 0 && Bytes > Max && !CapWarned) {
      CapWarned = true;
      fmt::print("snapfuzz: input of {} bytes exceeds the {}-byte guard page slack; "
                 "placing it without a guard page, so an overflow of THIS input will "
                 "not fault.\n",
                 Bytes, Max);
    }
  }

  // Only when the variable is genuinely ABSENT. Reaching here with a boundary set means
  // the input exceeded the cap, which the branch above already reported; printing "unset"
  // for that case would send the reader to look for a configuration problem that is not
  // there.
  static bool Warned = false;
  if (!Warned && (Env == nullptr || Env[0] == 0)) {
    Warned = true;
    fmt::print("snapfuzz: SNAPFUZZ_GUARD_BOUNDARY unset; placing the input at the tail "
               "of the pointer's page.\n"
               "  Whether the next page is unmapped has NOT been verified, so an "
               "overflow may land in\n"
               "  mapped memory and never fault. Run prep.guard_page to establish a "
               "boundary.\n");
  }
  return Gva_t((Pointer & ~(kPageSize - 1)) + (kPageSize - Bytes));
}

//
// The same, taking wtf's address type, because `Gva_t` has no implicit conversion to
// `uint64_t` and a caller holding one should not have to reach for `.U64()`.
//
inline Gva_t ResolveInputAddress(Gva_t Pointer, size_t Bytes) {
  return ResolveInputAddress(Pointer.U64(), Bytes);
}

} // namespace snapfuzz
