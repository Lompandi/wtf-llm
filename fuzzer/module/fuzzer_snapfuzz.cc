// snapfuzz fuzzer module (CLAUDE.md CP4).
//
// Modelled on src/wtf/fuzzer_tlv_server.cc, which CP4 names as the file to
// follow and section 13.8 calls "our primary model". It targets the same
// tlv_server snapshot; what makes it ours is the mutator, which is the
// sanctioned ingest path for LLM-generated seeds (section 12.1).
//
// THIS FILE IS NOT THE BUILD LOCATION. Its home is fuzzer/module/ because
// .gitignore:35 (`src/wtf/fuzzer_*`) would silently untrack it under src/wtf/
// -- see docs/DEVIATIONS.md D-012. fuzzer/build.py copies it into src/wtf/ at
// build time, where being ignored is correct.
//
// Three things here are load-bearing and were learned from the source, not
// assumed. Each has a comment where it applies:
//   * InsertTestcase returning false calls std::abort() (D-016).
//   * A Crash_t with an empty name is silently dropped by the master (D-018).
//   * GetNewTestcase runs on the MASTER's hot path and must never block (12.1).

#include "backend.h"
#include "crash_detection_umode.h"
#include "mutator.h"
#include "nlohmann/json.hpp"
#include "snapfuzz_resolve.h"
#include "targets.h"
#include "utils.h"

#include <cstdlib>
#include <deque>
#include <filesystem>
#include <fmt/format.h>
#include <string>
#include <system_error>
#include <vector>

namespace Snapfuzz {

namespace sfs = std::filesystem;

constexpr bool LoggingOn = false;

//
// The fuzz entry and the symbols we hook. Constants rather than literals
// scattered through the file: at CP6 these come from the LLM-chosen FuzzEntry
// in config/target.yaml, and this is the seam where that plugs in.
//
constexpr const char *kFuzzEntry = "tlv_server!ProcessPacket";
constexpr const char *kPrintf = "tlv_server!printf";

//
// Page-tail alignment. Writing the packet flush against the end of the page
// puts the guard page immediately after it, so a read past the buffer FAULTS
// instead of quietly succeeding. This is the one cheap compensation we get for
// having no ASAN (DECISIONS DEC-001, docs/DEVIATIONS.md D-031): it converts a
// class of out-of-bounds reads -- which section 2 lists as undetectable -- into
// observable access violations.
//
constexpr uint64_t kPageSize = 0x1000;

//
// The seed spool the slow-clock sidecar writes and this mutator drains
// (section 12.1). Read from the environment because a fuzzer module cannot see
// our YAML config.
//
constexpr const char *kSpoolEnvVar = "SNAPFUZZ_SEED_SPOOL";

template <typename... Args_t>
void DebugPrint(const char *Format, const Args_t &...args) {
  if constexpr (LoggingOn) {
    fmt::print("snapfuzz: ");
    fmt::print(fmt::runtime(Format), args...);
  }
}

//
// Wire format, identical to tlv_server's so the shipped corpus and the four
// labelled bugs in interesting/ remain usable (D-015). BodySize is deliberately
// separate from Body.size(): that inconsistency is what reaches the overflows.
//

struct Packet_t {
  uint32_t Command;
  uint16_t Id;
  uint16_t BodySize;
  std::vector<uint8_t> Body;

  //
  // How many bytes the target is told arrived, independent of how many we
  // wrote. 0 means "the natural size" (header + body).
  //
  // This exists because without it a whole branch is unreachable BY
  // CONSTRUCTION. ProcessPacket opens with `if (param_2 < 8) { ...error... }`,
  // and a harness that always reports 8 + Body.size() can never satisfy it --
  // no seed, LLM-generated or otherwise, can reach that path. CP7 found this
  // the hard way: the frontier offered the branch, the LLM correctly aimed at
  // it, and nothing could possibly have worked (docs/DEVIATIONS.md D-040).
  //
  // It is also realistic rather than a testing hack: a peer on a socket can
  // send fewer bytes than a header claims, so a harness unable to express that
  // is under-testing the target.
  //
  uint32_t WireSize = 0;
};

//
// Hand-written serialisers rather than NLOHMANN_DEFINE_TYPE_INTRUSIVE, because
// WireSize must be OPTIONAL and that macro requires every field to be present.
// The bundled nlohmann is 3.10.4 and the _WITH_DEFAULT variant only arrived in
// 3.11, so this is written out.
//
// Optional is not a nicety: no existing corpus file has the field, and `at()`
// on a missing key throws -- which InsertTestcase would catch and skip, silently
// rejecting the entire pre-existing corpus and every LLM seed that omits it.
//
inline void to_json(json::json &Json, const Packet_t &Packet) {
  Json = json::json{{"Command", Packet.Command},
                    {"Id", Packet.Id},
                    {"BodySize", Packet.BodySize},
                    {"Body", Packet.Body},
                    {"WireSize", Packet.WireSize}};
}

inline void from_json(const json::json &Json, Packet_t &Packet) {
  Json.at("Command").get_to(Packet.Command);
  Json.at("Id").get_to(Packet.Id);
  Json.at("BodySize").get_to(Packet.BodySize);
  Json.at("Body").get_to(Packet.Body);
  Packet.WireSize = Json.value("WireSize", uint32_t(0));
}

struct Packets_t {
  std::vector<Packet_t> Packets;
  NLOHMANN_DEFINE_TYPE_INTRUSIVE(Packets_t, Packets);
};

struct {
  std::deque<Packet_t> Packets;
  CpuState_t Context;

  void RestoreGprs(Backend_t *B) {
    const auto &C = Context;
    B->Rsp(C.Rsp);
    B->Rip(C.Rip);
    B->Rax(C.Rax);
    B->Rbx(C.Rbx);
    B->Rcx(C.Rcx);
    B->Rdx(C.Rdx);
    B->Rsi(C.Rsi);
    B->Rdi(C.Rdi);
    B->R8(C.R8);
    B->R9(C.R9);
    B->R10(C.R10);
    B->R11(C.R11);
    B->R12(C.R12);
    B->R13(C.R13);
    B->R14(C.R14);
    B->R15(C.R15);
  }
} GlobalState;

//
// InsertTestcase -- runs on the WORKER.
//
// It does NOT write guest memory. The testcase is a *sequence* of packets, and
// the target consumes one per call to ProcessPacket, so the write happens in
// the breakpoint callback below. That is the multi-packet pattern section 13.7
// points at for stateful targets.
//
// RETURN VALUE, from src/wtf/client.cc:102-104:
//     if (!Target.InsertTestcase(...)) { print; std::abort(); }
// `false` KILLS THE WORKER. It is not "skip this testcase". Every rejection of
// a malformed input therefore returns TRUE having done nothing.
//
bool InsertTestcase(const uint8_t *Buffer, const size_t BufferSize) {
  GlobalState.Packets.clear();

  if (Buffer == nullptr || BufferSize == 0) {
    // Empty input: nothing to deliver. ProcessPacket's callback will see an
    // empty deque and stop the testcase cleanly.
    return true;
  }

  //
  // The mutator emits JSON, but a corpus file can be anything -- including a
  // file some other tool dropped in. A parse failure is an uninteresting
  // testcase, NOT a broken harness, so swallow it and return true.
  //
  try {
    const auto &Root = json::json::parse(Buffer, Buffer + BufferSize);
    const auto &Deserialized = Root.get<Packets_t>();
    for (auto Packet : Deserialized.Packets) {
      GlobalState.Packets.emplace_back(std::move(Packet));
    }
  } catch (const std::exception &E) {
    DebugPrint("testcase is not valid JSON ({}), skipping\n", E.what());
    return true;
  }

  return true;
}

bool Init(const Options_t &Opts, const CpuState_t &State) {
  GlobalState.Context = State;

  const Gva_t Rsp = Gva_t(g_Backend->Rsp());
  const Gva_t ReturnAddress = Gva_t(g_Backend->VirtRead8(Rsp));

  //
  // The fuzz entry. Each hit delivers the next packet; an empty queue ends the
  // testcase.
  //
  if (!g_Backend->SetBreakpoint(kFuzzEntry, [](Backend_t *Backend) {
        if (GlobalState.Packets.empty()) {
          return Backend->Stop(Ok_t());
        }

        const auto &Testcase = GlobalState.Packets.front();
        const size_t PacketSize = sizeof(uint32_t) + sizeof(uint16_t) +
                                  sizeof(uint16_t) + Testcase.Body.size();

        //
        // Too big to place inside one page. Drop it and end the testcase --
        // note this is a Stop(Ok_t()), not a crash and not an abort.
        //
        if (PacketSize >= kPageSize) {
          GlobalState.Packets.pop_front();
          DebugPrint("packet of {} bytes does not fit a page, bailing\n",
                     PacketSize);
          return Backend->Stop(Ok_t());
        }

        //
        // size_param = rdx, in BYTES (config/target.yaml).
        //
        // WireSize, when set, reports FEWER (or more) bytes than we wrote --
        // modelling a short read on a socket. It is what makes the
        // `param_2 < 8` path reachable at all (D-040).
        //
        size_t ReportedSize = PacketSize;
        if (Testcase.WireSize != 0 && Testcase.WireSize < kPageSize) {
          ReportedSize = Testcase.WireSize;
        }
        Backend->Rdx(ReportedSize);

        //
        // input_param = rcx, which HOLDS the buffer address. Slide the write to
        // the tail of the page so the guard page sits immediately behind it.
        //
        // Aligned on the bytes actually WRITTEN, not on ReportedSize: the guard
        // page must sit behind the real data, or an over-reported size would
        // read our own bytes instead of faulting.
        //
        // Via the shared helper, which masks the pointer to its page and prefers a
        // VERIFIED unmapped boundary. This was `PageBase = Backend->Rcx()` followed by
        // `PageBase + (kPageSize - PacketSize)`, and a register is a POINTER, not a page
        // base -- so on an unaligned pointer the sum lands past the page end (D-078).
        //
        // It was benign HERE, and only by luck: this target's rcx is 0x20091325000, which
        // is already page-aligned, so the unmasked arithmetic gave the right answer. That
        // is why it survived long enough to be copied into both generators, one of which
        // ran against a target whose rcx is 0xd3d77ff7a0 and put the test-case 0x790 bytes
        // into an unmapped hole. A latent bug that is correct on the target you wrote it
        // for is the hardest kind to see.
        uint64_t PacketAddress =
            snapfuzz::ResolveInputAddress(Backend->Rcx(), PacketSize).U64();
        Backend->Rcx(PacketAddress);

        //
        // Field-by-field, matching the target's on-wire layout.
        //
        if (!Backend->VirtWriteStructDirty(Gva_t(PacketAddress),
                                           &Testcase.Command)) {
          fmt::print("snapfuzz: failed to write Command\n");
          std::abort();
        }
        PacketAddress += sizeof(Testcase.Command);

        if (!Backend->VirtWriteStructDirty(Gva_t(PacketAddress), &Testcase.Id)) {
          fmt::print("snapfuzz: failed to write Id\n");
          std::abort();
        }
        PacketAddress += sizeof(Testcase.Id);

        //
        // BodySize is written from the testcase, NOT from Body.size(). The
        // disagreement between them is the bug trigger; recomputing it here
        // would quietly neuter every overflow testcase.
        //
        if (!Backend->VirtWriteStructDirty(Gva_t(PacketAddress),
                                           &Testcase.BodySize)) {
          fmt::print("snapfuzz: failed to write BodySize\n");
          std::abort();
        }
        PacketAddress += sizeof(Testcase.BodySize);

        if (!Testcase.Body.empty() &&
            !Backend->VirtWriteDirty(Gva_t(PacketAddress), Testcase.Body.data(),
                                     Testcase.Body.size())) {
          fmt::print("snapfuzz: failed to write Body\n");
          std::abort();
        }

        GlobalState.Packets.pop_front();
      })) {
    fmt::print("snapfuzz: failed to SetBreakpoint on {}\n", kFuzzEntry);
    return false;
  }

  //
  // Back at the caller: restore the GPRs so the next packet is delivered from
  // the same state. The snapshot restore does not cover this because we are
  // looping WITHIN one testcase, not between testcases -- which is exactly the
  // residual state RULE 4's Restore question is about (DECISIONS R2).
  //
  if (!g_Backend->SetBreakpoint(ReturnAddress, [](Backend_t *Backend) {
        GlobalState.RestoreGprs(Backend);
        DebugPrint("back at the entry point, ready for the next packet\n");
      })) {
    fmt::print("snapfuzz: failed to SetBreakpoint on the return address\n");
    return false;
  }

  //
  // Silence the target's printf. It is pure I/O noise and costs real time at
  // hundreds of executions per second.
  //
  if (!g_Backend->SetBreakpoint(kPrintf, [](Backend_t *Backend) {
        const Gva_t FormatPtr = Backend->GetArgGva(0);
        DebugPrint("printf: {}", Backend->VirtReadString(FormatPtr));
        Backend->SimulateReturnFromFunction(0);
      })) {
    fmt::print("snapfuzz: failed to SetBreakpoint on {}\n", kPrintf);
    return false;
  }

  //
  // THE CRASH ORACLE. wtf infers nothing (section 13.7) -- this call installs
  // the user-mode fault hooks (nt!KeBugCheck2, ntdll!RtlDispatchException,
  // verifier!VerifierStopMessage, ...). Each produces a NAMED Crash_t, which
  // matters: the master silently discards a crash whose name is empty
  // (server.h:861-866, D-018).
  //
  if (!SetupUsermodeCrashDetectionHooks()) {
    fmt::print("snapfuzz: failed to SetupUsermodeCrashDetectionHooks\n");
    return false;
  }

  return true;
}

//
// Per-iteration reset. The snapshot restore handles guest memory and registers;
// the only residual state we own is the packet queue, and InsertTestcase clears
// that before each testcase. Restoring it twice would be as wrong as not
// restoring it, so this stays a no-op (DECISIONS R2).
//
bool Restore() { return true; }

//
// The mutator -- runs on the MASTER (section 12.1, edge 21a).
//
// If this class is not registered, the master silently falls back to a built-in
// mutator and EVERY LLM seed is ignored while coverage keeps climbing. That is
// why tests/gates/test_graph.py asserts edges 21a and 21b are both live.
//
class CustomMutator_t : public Mutator_t {
  std::unique_ptr<uint8_t[]> ScratchBuffer__;
  span_u8 ScratchBuffer_;
  size_t TestcaseMaxSize_ = 0;
  std::mt19937_64 &Rng_;
  sfs::path SpoolPath_;
  uint64_t SpoolServed_ = 0;

public:
  //
  // CP10's baseline arms select a BUILT-IN mutator here.
  //
  // wtf has no --mutator flag: which mutator runs is decided by what the module
  // registers, so the only way to measure our mutator against wtf's own is for
  // this factory to hand back a built-in when asked. SNAPFUZZ_MUTATOR takes
  // "libfuzzer" or "honggfuzz"; anything else, including unset, gives ours.
  //
  // Note precisely what this does and does not hold fixed. Init, InsertTestcase
  // and Restore stay OURS in every arm -- they are the harness that delivers
  // packets, without which nothing runs at all. So the comparison isolates
  // test-case *generation*, which is the contribution, and does not claim to
  // measure a from-scratch wtf harness.
  //
  static std::unique_ptr<Mutator_t> Create(std::mt19937_64 &Rng,
                                           const size_t TestcaseMaxSize) {
    if (const char *Env = std::getenv("SNAPFUZZ_MUTATOR"); Env && *Env) {
      const std::string Which(Env);
      if (Which == "libfuzzer") {
        fmt::print("snapfuzz: BASELINE arm -- using wtf's libfuzzer mutator\n");
        return LibfuzzerMutator_t::Create(Rng, TestcaseMaxSize);
      }
      if (Which == "honggfuzz") {
        fmt::print("snapfuzz: BASELINE arm -- using wtf's honggfuzz mutator\n");
        return HonggfuzzMutator_t::Create(Rng, TestcaseMaxSize);
      }
      if (Which != "custom") {
        // Refuse rather than silently running the wrong arm: a typo here would
        // label our own mutator's numbers as a baseline.
        fmt::print(
            "snapfuzz: SNAPFUZZ_MUTATOR={} is not one of libfuzzer/honggfuzz/"
            "custom; refusing to guess which arm this is\n",
            Which);
        // abort() does not flush C stdio, and without this the process dies with
        // exit code 0xC0000409 and no explanation at all -- which is worse than
        // the typo it is complaining about.
        std::fflush(stdout);
        std::abort();
      }
    }
    return std::make_unique<CustomMutator_t>(Rng, TestcaseMaxSize);
  }

  explicit CustomMutator_t(std::mt19937_64 &Rng, const size_t TestcaseMaxSize)
      : Rng_(Rng), TestcaseMaxSize_(TestcaseMaxSize) {
    ScratchBuffer__ = std::make_unique<uint8_t[]>(_1MB);
    ScratchBuffer_ = {ScratchBuffer__.get(), _1MB};

    if (const char *Env = std::getenv(kSpoolEnvVar); Env && *Env) {
      SpoolPath_ = Env;
      fmt::print("snapfuzz: seed spool at {}\n", SpoolPath_.string());
    } else {
      fmt::print("snapfuzz: no {} set; running without LLM seed ingest\n",
                 kSpoolEnvVar);
    }
  }

  //
  // HOT PATH. Called once per test-case, on the master, with every worker
  // waiting. It must never block (section 12.1) -- so the spool check is a
  // best-effort directory peek that falls straight through on anything
  // unexpected, and NEVER waits on a lock or a network.
  //
  std::string GetNewTestcase(const Corpus_t &Corpus) override {
    if (auto Seed = TryTakeSpooledSeed(); Seed.has_value()) {
      SpoolServed_++;
      DebugPrint("served LLM seed #{}\n", SpoolServed_);
      return std::move(*Seed);
    }

    if (GetUint32(1, 5) == 5) {
      return Generate();
    }

    const Testcase_t *Testcase = Corpus.PickTestcase();
    if (!Testcase) {
      // An empty corpus means the run was started with no seeds at all.
      return Generate();
    }

    memcpy(ScratchBuffer_.data(), Testcase->Buffer_.get(),
           Testcase->BufferSize_);
    return Mutate(ScratchBuffer_.data(), Testcase->BufferSize_,
                  ScratchBuffer_.size_bytes());
  }

private:
  //
  // Take at most ONE seed from the spool and delete it.
  //
  // Ownership (RULE 4, DECISIONS R9): the CONSUMER deletes. The sidecar writes
  // atomically (temp file then rename) so a half-written seed is never visible,
  // and this end removes the file once it has the bytes. A file that vanishes
  // between listing and reading is another process winning the race, which is
  // fine -- we just fall through to the built-in mutator this iteration.
  //
  std::optional<std::string> TryTakeSpooledSeed() {
    if (SpoolPath_.empty()) {
      return std::nullopt;
    }

    std::error_code Ec;
    sfs::directory_iterator It(SpoolPath_, Ec);
    if (Ec) {
      // Missing directory is normal before the sidecar starts.
      return std::nullopt;
    }

    for (const auto &Entry : It) {
      if (!Entry.is_regular_file(Ec) || Ec) {
        continue;
      }

      // Only fully-renamed seeds. A ".tmp" is a write in progress.
      const auto &Path = Entry.path();
      if (Path.extension() == ".tmp") {
        continue;
      }

      std::ifstream File(Path, std::ios::binary);
      if (!File) {
        continue; // lost the race; someone else took it
      }
      std::string Contents((std::istreambuf_iterator<char>(File)),
                           std::istreambuf_iterator<char>());
      File.close();

      sfs::remove(Path, Ec); // consumer deletes; ignore failure
      if (Contents.empty()) {
        continue;
      }
      return Contents;
    }

    return std::nullopt;
  }

  std::string Generate() {
    Packets_t Root;
    const auto N = GetUint32(1, 10);
    for (size_t Idx = 0; Idx < N; Idx++) {
      Packet_t Packet;
      Packet.Id = uint16_t(Idx);
      Packet.Command = GetUint32(0, 10);
      Packet.Body.resize(GetUint32(0, 100));
      Packet.BodySize = uint16_t(Packet.Body.size());

      // Sometimes desynchronise BodySize from the real body length. This is
      // the inconsistency the target's overflow paths key on.
      if (GetUint32(1, 3) == 1) {
        Packet.BodySize ^= 1 << GetUint32(0, 15);
      }

      // And occasionally report a short wire size, which is the only way to
      // reach a "packet too small" guard (D-040).
      if (GetUint32(1, 8) == 1) {
        Packet.WireSize = GetUint32(0, 8);
      }

      Root.Packets.emplace_back(Packet);
    }

    json::json Serialized;
    to_json(Serialized, Root);
    return Serialized.dump();
  }

  std::string Mutate(uint8_t *Data, const size_t DataLen,
                     const size_t MaxSize) {
    enum Transformation_t : uint32_t {
      Start,
      InsertPacket = Start,
      CopyField,
      DeletePacket,
      CorruptBodySize,
      TruncateWire,
      End = TruncateWire
    };

    Packets_t Root;
    try {
      const auto &Parsed = json::json::parse(Data, Data + DataLen);
      Root = Parsed.get<Packets_t>();
    } catch (const std::exception &) {
      // Corpus entry is not our format -- start from a fresh one rather than
      // aborting the master.
      return Generate();
    }

    auto &Packets = Root.Packets;
    if (Packets.empty()) {
      return Generate();
    }

    switch (Transformation_t(GetUint32(Start, End))) {
    case InsertPacket:
      MutationInsertPacket(Packets);
      break;
    case CopyField:
      MutationCopyField(Packets);
      break;
    case DeletePacket:
      MutationDeletePacket(Packets);
      break;
    case CorruptBodySize:
      MutationCorruptBodySize(Packets);
      break;
    case TruncateWire:
      MutationTruncateWire(Packets);
      break;
    }

    json::json Serialized;
    to_json(Serialized, Root);
    return Serialized.dump();
  }

  uint32_t GetUint32(const uint32_t A, const uint32_t B) {
    return std::uniform_int_distribution<uint32_t>(A, B)(Rng_);
  }

  void MutationCopyField(std::vector<Packet_t> &Packets) {
    const uint32_t SrcIdx = GetUint32(0, uint32_t(Packets.size()) - 1);
    const uint32_t DstIdx = GetUint32(0, uint32_t(Packets.size()) - 1);
    const auto &Src = Packets[SrcIdx];
    auto &Dst = Packets[DstIdx];
    switch (GetUint32(0, 3)) {
    case 0:
      Dst.Id = Src.Id;
      break;
    case 1:
      Dst.Command = Src.Command;
      break;
    case 2:
      Dst.BodySize = Src.BodySize;
      break;
    case 3:
      Dst.Body = Src.Body;
      break;
    }
  }

  void MutationInsertPacket(std::vector<Packet_t> &Packets) {
    if (Packets.size() > 10) {
      return;
    }
    const uint32_t FromIdx = GetUint32(0, uint32_t(Packets.size()) - 1);
    const uint32_t ToIdx = GetUint32(0, uint32_t(Packets.size()));
    Packets.insert(Packets.begin() + ToIdx, Packets[FromIdx]);
  }

  void MutationDeletePacket(std::vector<Packet_t> &Packets) {
    if (Packets.size() <= 1) {
      return;
    }
    const uint32_t SrcIdx = GetUint32(0, uint32_t(Packets.size()) - 1);
    Packets.erase(Packets.begin() + SrcIdx);
  }

  //
  // Ours, not in fuzzer_tlv_server.cc: flip BodySize away from the real body
  // length directly, rather than only via Generate(). This is the structural
  // fixup CP4 talks about, applied in reverse -- we deliberately BREAK the
  // length invariant because that is what reaches the memcpy.
  //
  void MutationCorruptBodySize(std::vector<Packet_t> &Packets) {
    const uint32_t Idx = GetUint32(0, uint32_t(Packets.size()) - 1);
    auto &Packet = Packets[Idx];
    switch (GetUint32(0, 2)) {
    case 0:
      Packet.BodySize ^= 1 << GetUint32(0, 15);
      break;
    case 1:
      Packet.BodySize = uint16_t(Packet.Body.size() + GetUint32(1, 0x100));
      break;
    case 2:
      Packet.BodySize = 0xffff;
      break;
    }
  }

  //
  // Report a short wire size. Ours, and the only way to exercise a header-size
  // guard: without it `if (param_2 < 8)` is unreachable however the body is
  // mutated, because the harness would always claim 8 + Body.size() (D-040).
  //
  void MutationTruncateWire(std::vector<Packet_t> &Packets) {
    auto &Packet = Packets[GetUint32(0, uint32_t(Packets.size()) - 1)];
    // 0 restores the natural size, so include it to undo a truncation too.
    Packet.WireSize = GetUint32(0, 12);
  }
};

//
// Register the target. ONE artifact, loaded by BOTH the master (which uses
// CustomMutator_t) and every worker (which uses Init / InsertTestcase /
// Restore) -- edges 21a and 21b.
//
Target_t Snapfuzz("snapfuzz", Init, InsertTestcase, Restore,
                  CustomMutator_t::Create);

} // namespace Snapfuzz
