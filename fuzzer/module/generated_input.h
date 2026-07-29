// GENERATED FILE -- do not edit by hand.
//
// Produced by fuzzer/codegen.py from an InputSpec that
// prep/input_struct.py derived from Ghidra pseudo-C (CLAUDE.md edges 12 and 14).
// Regenerate with:
//
//     python -m fuzzer.codegen --spec D:\wtf-llm\artifacts\fuzzing-test-cmp\input_spec.json --out <this file>
//
// Target : fuzzing-test-cmp!FUN_1400447c0
// Source : FUN_1400447c0, FUN_140044aa0
//
// Why the shape is this, per the model:
//   The parser expects a 4-byte magic value, followed by a 1-byte length field, then that many bytes of payload. The magic is validated first; if it matches the function proceeds, otherwise it rejects. The length field determines the size of the following payload, which is read as a raw byte array.
//
// Hand-written code -- Init, InsertTestcase, Restore, the crash oracle, the
// mutator -- lives in the module that includes this header. Those encode
// decisions about residual state and crash conditions that no description of an
// input format implies, and they are deliberately NOT generated (section 3.1's
// "Manual tweaks" box).
//
#pragma once

#include <cstdint>
#include <cstring>
#include <vector>

namespace snapfuzz_generated {

//
// Little-endian append. The guest is x86-64, so a plain memcpy of the host
// representation is already little-endian; this is written out rather than
// memcpy'd wholesale because a struct copy would also copy padding the target
// never sees.
//
template <typename T> inline void Append(std::vector<uint8_t> &Out, const T Value) {
  const auto *Bytes = reinterpret_cast<const uint8_t *>(&Value);
  Out.insert(Out.end(), Bytes, Bytes + sizeof(T));
}

template <typename T>
inline void AppendBigEndian(std::vector<uint8_t> &Out, const T Value) {
  for (size_t Idx = sizeof(T); Idx-- > 0;) {
    Out.push_back(static_cast<uint8_t>((Value >> (Idx * 8)) & 0xff));
  }
}

struct FuzzPacket {
  // magic; parser compares against 0x5a5a5546 -- The first 4 bytes at offset 0 are compared with constant 0x5a5a5546 ("FUZZ") via memcmp(param_1,&DAT_1400c6174,4).
  uint32_t magic = 0x5a5a5546;
  // length; counts payload in elements -- Byte at offset 4 (param_1[4]) is read as a length value that tells how many payload bytes follow.
  uint8_t total_len;
  // bytes; capped at 255 bytes -- Variable length data after the length byte; the number of bytes to read is given by the total_len field.
  std::vector<uint8_t> payload;

  //
  // How many bytes the target is TOLD arrived, independent of how many were
  // written. 0 means the natural size.
  //
  // Without this a guard like `if (size < header) reject` is unreachable BY
  // CONSTRUCTION -- no seed can satisfy it, however well reasoned. CP7 measured
  // exactly that: the frontier offered the branch, the model aimed at it
  // correctly, and nothing could have worked (D-040). It is also realistic: a
  // peer on a socket can send fewer bytes than its header claims.
  //
  uint32_t WireSize = 0;
};

//
// Fixed-size prefix, in bytes. 5 = 4 + 1
//
constexpr size_t kFuzzPacketHeaderBytes = 5;

//
// Serialise one FuzzPacket to the bytes the target will parse.
//
// Length fields are RECOMPUTED here from the actual payload, which is the
// structural fixup CP4 requires: a mutator that flips a length byte would
// otherwise produce a test-case the parser discards at its first bounds check.
//
inline std::vector<uint8_t> Serialize(const FuzzPacket &Packet) {
  std::vector<uint8_t> Out;
  Out.reserve(kFuzzPacketHeaderBytes + Packet.payload.size());

  // magic (uint32_t, 4 byte(s))
  Append(Out, Packet.magic);

  // total_len (uint8_t, 1 byte(s))
  // Recomputed, NOT taken from the test-case: a mutated length that
  // disagrees with the payload is rejected at the parser's first
  // check, and that is the difference between 5% and 50% coverage
  // (CLAUDE.md CP4).
  const uint8_t total_lenValue =
      static_cast<uint8_t>(Packet.payload.size()  /* elements == bytes here */);
  Append(Out, total_lenValue);

  // payload: variable-length tail
  Out.insert(Out.end(), Packet.payload.begin(),
             Packet.payload.end());

  return Out;
}

//
// The size to report to the target for this packet.
//
inline uint32_t ReportedSize(const FuzzPacket &Packet,
                             const size_t ActualBytes) {
  return Packet.WireSize ? Packet.WireSize
                         : static_cast<uint32_t>(ActualBytes);
}

} // namespace snapfuzz_generated
