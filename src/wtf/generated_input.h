// GENERATED FILE -- do not edit by hand.
//
// Produced by fuzzer/codegen.py from an InputSpec that
// prep/input_struct.py derived from Ghidra pseudo-C (CLAUDE.md edges 12 and 14).
// Regenerate with:
//
//     python -m fuzzer.codegen --spec D:\wtf-llm\artifacts\fuzzing-base-test\input_spec.json --out <this file>
//
// Target : fuzzing-base-test!fuzzme
// Source : fuzzme, FUN_1400011a0
//
// Why the shape is this, per the model:
//   The parser expects a 4-byte magic "test" followed by a 1-byte length field that indicates how many subsequent bytes constitute the payload. The payload may be up to 0x41 bytes; the total buffer is limited to 32 bytes, and the length field is after the magic. The entry function validates the magic and length before processing the payload, and it is invoked only once per test case, so the format does not support a sequence of packets.
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

struct Packet_t {
  // magic; parser compares against 0x74736574 -- The code checks param_1[0]=='t', param_1[1]=='e', param_1[2]=='s', param_1[3]=='t' which together form the ASCII string "test"; interpreted as a 32-bit little-endian magic value 0x74736574.
  uint32_t magic = 0x74736574;
  // length; counts payload in bytes -- param_1[4] is used as the length for the following payload (passed as the third argument to FUN_14001b1b0). The code only processes a payload when the total input length exceeds 4 bytes.
  uint8_t payload_len;
  // bytes; capped at 65 bytes -- The remaining bytes of the 32-byte buffer up to the length indicated by payload_len are processed; the function is called with a constant 0x41 which appears to be an upper bound for the payload size. Terminated by 0x00: fuzzme opens with while (param_1[i] != 0) i++, so the buffer is a C string and an unterminated input makes that scan read past the end of the data. Set after the derivation missed it -- the scan is the first statement in the pseudo-C.
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
constexpr size_t kPacket_tHeaderBytes = 5;

//
// Serialise one Packet_t to the bytes the target will parse.
//
// Length fields are RECOMPUTED here from the actual payload, which is the
// structural fixup CP4 requires: a mutator that flips a length byte would
// otherwise produce a test-case the parser discards at its first bounds check.
//
inline std::vector<uint8_t> Serialize(const Packet_t &Packet) {
  std::vector<uint8_t> Out;
  Out.reserve(kPacket_tHeaderBytes + Packet.payload.size());

  // magic (uint32_t, 4 byte(s))
  Append(Out, Packet.magic);

  // payload_len (uint8_t, 1 byte(s))
  // Recomputed, NOT taken from the test-case: a mutated length that
  // disagrees with the payload is rejected at the parser's first
  // check, and that is the difference between 5% and 50% coverage
  // (CLAUDE.md CP4).
  const uint8_t payload_lenValue =
      static_cast<uint8_t>(Packet.payload.size());
  Append(Out, payload_lenValue);

  // payload: variable-length tail
  Out.insert(Out.end(), Packet.payload.begin(),
             Packet.payload.end());
  // delimited by 0x00, not counted -- the parser reads until this byte
  Out.push_back(uint8_t(0x00));

  return Out;
}

//
// The size to report to the target for this packet.
//
inline uint32_t ReportedSize(const Packet_t &Packet,
                             const size_t ActualBytes) {
  return Packet.WireSize ? Packet.WireSize
                         : static_cast<uint32_t>(ActualBytes);
}

} // namespace snapfuzz_generated
