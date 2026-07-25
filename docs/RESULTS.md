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
