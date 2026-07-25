# RESULTS

Evaluation numbers (CLAUDE.md CP10 / GATE 10). **Empty by design** — nothing
here until there is a measured run to put in it.

GATE 10 requires, for at least one target:

- **vanilla wtf vs the LLM-guided system**, same target, same time budget, same
  initial seeds;
- metrics: time-to-first-crash, coverage growth curve, unique crash buckets;
- both ablations: (a) no LLM seed generation, (b) no pseudo-C in prompts;
- coverage curves plotted.

Without that comparison the project's central claim is unsupported, so this
file is on the critical path, not an afterthought.

Two results land here earlier than CP10 and should be recorded as they happen:

- **GATE 7** — coverage before and after the first LLM seed injection on at
  least one target. CLAUDE.md calls this a headline result.
- **GATE 9** — triage precision and recall on the **held-out** planted-bug
  split. The split itself is recorded in DECISIONS.md; reporting numbers from
  the split used for DSPy optimisation is invalid (section 10).

Every number here must name the target, the backend, the wall-clock budget, the
seed set and the commit it was produced at. A coverage figure without its
backend is not interpretable — bochscpu and whv do not measure the same thing
(DEVIATIONS D-004).

---

## CP7 — the slow clock on `tlv_server`

**Setup.** Target `tlv_server.exe`, fuzz entry `ProcessPacket`, backend
`bochscpu`, 2 workers, one master, one slow-clock sidecar process. Corpus started
from **one deliberately poor seed** (a single Allocate with an empty body) and an
empty `outputs/`, which is the induced plateau GATE 7's own text asks for. A
previous attempt measured against a 44-entry corpus inherited from the CP4/CP4b
runs; that was the wrong control, because the mutator had already found
everything reachable and any LLM contribution was being measured against a
saturated baseline.

### What the slow clock does, measured

| | |
|---|---|
| Run | 1321 s, 864,729 executions, 2 workers, `bochscpu` |
| Plateau trigger | fired on the **execution** signal §12.3 requires — "65444 executions without new coverage" — not the wall-clock safety net |
| Workers running at plateau | 2; 104 of 105 parsed stat lines report `nodes: 2` |
| Seed-gen rounds | 1 per plateau, as the gate requires (the detector re-arms only on new coverage) |
| Seeds published | 12, from 2 independent samples, 0 cross-sample duplicates |
| Seeds consumed | 12 of 12 — `spool_depth` was 0 on the publish log line, i.e. the master's mutator drained the spool as fast as the sidecar wrote it |
| LLM time in the round | 72.8 s |
| Fuzzer throughput | mean 774 exec/s, min 545, across a run containing the LLM round; the fast loop never waited |
| Coverage | 22 blocks (poor seed alone) → **48** at injection → **48** final |

Those four are GATE 7's criteria 1, 2, 4 and 5. The fifth — **coverage increases
after injection** — was **not** achieved on this target, and the reason is
quantified rather than guessed.

### Why the coverage delta was zero, in numbers

`ProcessPacket` has 38 basic blocks. From the single poor seed, wtf's own
mutator covered 33 of them within roughly 100 seconds and then covered nothing
further for the remaining ~20 minutes and ~600,000 executions. The five
uncovered blocks are the entire space available to the slow clock, and they split
two ways.

**Two are dead code.** `0x1400012de` and `0x1400012ed` are the two
`operator delete[]` arms of the inlined `unique_ptr<uint8_t[]>` move-assignment,
each guarded by a null test the emitted code cannot satisfy — `0x1400012ed`
tests the moved-from temporary that the move zeroes one instruction earlier,
and `0x1400012de` tests the destination's previous `Buf`, which
`make_unique<Chunk_t>` has already zeroed. Verified adversarially through two
independent lenses: a disassembly-level argument, and **454 measured executions**
of which 409 were inputs written specifically to reach them (an allocation sweep
to 200, identical-id runs, Delete/Allocate orderings, a 70-point Edit-overflow
sweep, a 240-input randomised sweep). Every batch carried a positive control, and
198 of those inputs did light up `0x14000131c` — so the harness was demonstrably
working and the negative is not vacuous. Neither block was ever reached.

**Three are reachable, behind one exact threshold.** `0x14000131c` and its two
successors need **six** Allocate commands in one test-case, with no intervening
Delete. `ChunkList` holds four slots (`0x140006a18`–`0x140006a38`); allocations
1–4 fill it; allocation 5 finds no free slot, runs off the end, and writes a
`Chunk_t*` **out of bounds** over the adjacent CRT function pointer
`__dyn_tls_dtor_callback`, which is NULL in this snapshot so the null test still
takes the null path; allocation 6 reads that out-of-bounds slot back as a
`Chunk_t*` and frees it. Measured, not inferred: allocations 1–5 do not reach it,
6–11 do.

### The finding worth keeping

Coverage as a function of allocation count, one `wtf run` per count
(`eval/coverage_gradient.py`):

| Allocations | Blocks | New |
|---|---|---|
| 1 | 22 | — |
| 2 | 23 | +1 |
| 3 | 23 | **+0** |
| 4 | 23 | **+0** |
| 5 | 23 | **+0** ← the out-of-bounds write happens here |
| 6 | 30 | **+7** |
| 7–11 | 30 | +0 |

Three consecutive zero-reward steps before the reward. A coverage-guided mutator
has **no gradient** across that gap: nothing prefers four allocations to three, or
five to four, so it cannot accumulate its way to six. Measurement agrees — after
864,729 executions the retained corpus topped out at exactly **4** allocations,
the table's capacity, one short of the out-of-bounds write.

And the write itself is **invisible to coverage**: it happens at five allocations
and covers nothing new. Only the *subsequent free* of the clobbered function
pointer, at six, produces a coverage signal. This is CLAUDE.md §2's stated
limitation made concrete on a real target — the binary-only oracle sees
observable faults only, and here even the coverage signal that might have drawn a
fuzzer toward the corruption is absent.

### What the LLM did and did not do

It identified the right mechanism unprompted. One round's `analysis` field read:
*"…or exhaust the chunk table before delete, forcing the cleanup path."* Given
`ChunkList`'s capacity from Ghidra (Contribution 2 — the fact decompilation
drops, see D-047), it proposed sequences of exactly **four** allocations: it
filled the table rather than overflowing it. Supplying the capacity was necessary
and not sufficient; the remaining inference is that the overflow slot must be
populated by an earlier out-of-bounds write before the read can observe it.

Across every round measured on this frontier, the longest sequence proposed was
**5** allocations and the median was 1–2. A re-sampled 18-seed round, in which the
prompt reported all three branches as already tried and still unreached, proposed
at most **2** — shorter, not longer. Those seeds do execute properly (they cover
47 of the corpus's 48 blocks), so this is a reasoning ceiling, not a plumbing
failure.

**Two of the mechanisms added this checkpoint did not pay off, and are reported as
such.** The already-tried feedback list (D-044) did not push the model toward a
different mechanism on this target. Multi-sample rounds (D-048) removed the
round-to-round coin flip — one sample had proposed a 5-allocation sequence and the
next nothing longer than 1 — but raised the ceiling not at all. Neither result
shows the mechanisms are wrong; neither shows they work. They need a target where
the reward is more than one inference away.

**Honest reading.** On this target the slow clock's plumbing is proven end to end
and its reasoning gets close, but the one branch available to it sits behind a
two-step inference it did not make. `tlv_server` is a poor showcase for the
coverage claim: 33 of 38 blocks fall to random mutation in 100 seconds, and the
remainder is two dead blocks plus one six-deep insight. A target with genuine
headroom — a magic value, a checksum, a length relation — is what CP10's
`eval/planted_bugs/` is for, and the coverage claim should be made there. That
work needs a snapshot of a new binary, which is a dependency outside this
checkpoint.

**Note on the verification.** `tlv_server` ships with source in wtf's repo, and
the adjudication above used it to settle the dead-code question. The *pipeline*
never did: seed generation saw only Ghidra pseudo-C, the block graph, and the
global-symbol table. The source was used to check our claim, not to produce it.
