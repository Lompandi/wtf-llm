// GENERATED FILE -- do not edit by hand.
//
// Produced by fuzzer/codegen.py from an InputSpec that
// prep/input_struct.py derived from Ghidra pseudo-C (CLAUDE.md edges 12 and 14).
// Regenerate with:
//
//     python -m fuzzer.codegen --spec C:\Users\Caspe\AppData\Local\Temp\spec_aliased.json --out <this file>
//
// Target : tlv_server!ProcessPacket
// Source : ProcessPacket, main
//
// Why the shape is this, per the model:
//   The packet format begins with a 4-byte command (offset 0), a 2-byte header field (offset 4), and a 2-byte payload length (offset 6). The payload starts at offset 8 and its size is given by the length field. The caller supplies the total packet size, but the parser only uses the fields described.
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
  // scalar -- iVar2 = *(int *)param_1; // command ID at offset 0
  uint32_t Cmd;
  // scalar -- *(undefined2 *)(param_1 + 4) // stored into local_res8 at offset 4
  uint16_t HeaderInfo;
  // length; counts Payload in bytes -- (ulonglong)*(ushort *)((longlong)local_res8._Mypair._Myval2 + 2) // length of payload used for memcpy
  uint16_t PayloadSize;
  // bytes; capped at 65535 bytes -- memcpy(*(void **)_Var1._Myval2, param_1 + 8, (ulonglong)*(ushort *)((longlong)local_res8._Mypair._Myval2 + 2)); // copies PayloadSize bytes from offset 8
  std::vector<uint8_t> Payload;

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
// Fixed-size prefix, in bytes. 8 = 4 + 2 + 2
//
constexpr size_t kPacket_tHeaderBytes = 8;

//
// Serialise one Packet_t to the bytes the target will parse.
//
// Length fields are RECOMPUTED here from the actual payload, which is the
// structural fixup CP4 requires: a mutator that flips a length byte would
// otherwise produce a test-case the parser discards at its first bounds check.
//
inline std::vector<uint8_t> Serialize(const Packet_t &Packet) {
  std::vector<uint8_t> Out;
  Out.reserve(kPacket_tHeaderBytes + Packet.Payload.size());

  // Cmd (uint32_t, 4 byte(s))
  Append(Out, Packet.Cmd);

  // HeaderInfo (uint16_t, 2 byte(s))
  Append(Out, Packet.HeaderInfo);

  // PayloadSize (uint16_t, 2 byte(s))
  // Recomputed, NOT taken from the test-case: a mutated length that
  // disagrees with the payload is rejected at the parser's first
  // check, and that is the difference between 5% and 50% coverage
  // (CLAUDE.md CP4).
  const uint16_t PayloadSizeValue =
      static_cast<uint16_t>(Packet.Payload.size());
  Append(Out, PayloadSizeValue);

  // Payload: variable-length tail
  Out.insert(Out.end(), Packet.Payload.begin(),
             Packet.Payload.end());

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
