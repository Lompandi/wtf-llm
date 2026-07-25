"""GHSA-format report assembly (CLAUDE.md CP9, edges 42-43).

**Ordinary code, not an LLM.** Section 9 is explicit: triage produces the
verdicts, and assembling them into a report is templating. An LLM here would add
a second place for facts to drift from the evidence.

What ships and what does not
----------------------------
Only ``verdict == "confirmed"`` reaches the report. ``false_positive`` goes to a
discard log, which is **kept for evaluation** rather than deleted -- it is how the
triage prompt gets measured, and throwing it away would make regressions
invisible.

Honesty requirements the template enforces
------------------------------------------
Every finding carries the limits of how it was found, because a GHSA advisory that
implies more certainty than a binary-only oracle can provide is the kind of thing
that gets a report dismissed wholesale:

* the oracle sees observable faults only; silent memory corruption is out of scope
  (section 2);
* the analysis is that of a decompiler, not source, so names are inferred;
* determinism claims name the backend, because only bochscpu is fully
  deterministic (section 13.5);
* the dedup rung is stated, so a hit count from a coarse bucket is not read as
  evidence of a single bug's frequency.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from jinja2 import Environment, StrictUndefined

from analysis.classify import Classification
from analysis.reverse import CrashContext
from arch.contracts import CrashBucket, ReplayResult, TraceRef, TriageVerdict

REPO_ROOT = Path(__file__).resolve().parents[1]

__all__ = ["Finding", "render_report", "write_report"]

# Ordered worst-first. Used to sort findings, so the reader meets the most
# serious thing first rather than whatever happened to be bucket 1.
SEVERITY_ORDER = ("possible_rce", "info_leak", "dos", "unknown")


@dataclass
class Finding:
    """One confirmed verdict with the evidence behind it."""

    verdict: TriageVerdict
    bucket: CrashBucket
    classification: Classification | None = None
    replay: ReplayResult | None = None
    trace: TraceRef | None = None
    context: CrashContext | None = None

    @property
    def severity_rank(self) -> int:
        try:
            return SEVERITY_ORDER.index(self.verdict.exploitability)
        except ValueError:
            return len(SEVERITY_ORDER)

    @property
    def title(self) -> str:
        access = (self.classification.access if self.classification else "unknown")
        where = (
            self.context.function
            if self.context and self.context.function
            else "an unidentified function"
        )
        kind = {
            "write": "Out-of-bounds write",
            "read": "Out-of-bounds read",
        }.get(access, "Memory-safety fault")
        return f"{kind} reachable from {where}"


_TEMPLATE = """# Security advisory -- {{ target }}

*Generated {{ generated }} by snapfuzz (LLM-guided snapshot fuzzing).*

{{ findings | length }} confirmed finding(s){% if discarded %}, {{ discarded }} triaged
as false positives and logged separately{% endif %}.

## How these were found, and what that does not tell you

The target was fuzzed as a **binary, without source**, using snapshot fuzzing
(wtf) with coverage from breakpoints on basic blocks enumerated by Ghidra. Read
the following before treating any severity below as settled:

- **There is no sanitizer.** The crash oracle observes faults the platform
  reports -- access violations, aborts, illegal instructions, timeouts. Memory
  corruption that does not fault is **not detected**, so the absence of a finding
  is not evidence of safety.
- **The code analysis is decompiler output, not source.** Function and variable
  names may be invented and types are inferred.
- **Determinism claims name their backend.** Only `bochscpu` is fully
  deterministic; a result from another backend is qualified where it appears.
- **Crash counts are per bucket, and the bucketing rule is stated per finding.**
  A coarse rule can merge distinct bugs, so a high count is not by itself
  evidence about one bug.
{% for finding in findings %}
---

## {{ loop.index }}. {{ finding.title }}

| | |
|---|---|
| Severity assessment | **{{ finding.verdict.exploitability }}** |
| CWE | {{ finding.verdict.cwe_guess or "not determined" }} |
| Triage confidence | {{ "%.2f"|format(finding.verdict.confidence) }} |
| Crashes in this bucket | {{ finding.bucket.hit_count }} |
| Bucketing rule | `{{ finding.bucket.key_kind }}` -- {{ finding.bucket.key_detail | cell }} |
| Reproducer | {{ finding.bucket.representative.input_bytes|length }} bytes |
{% if finding.replay %}| Reproduced | {{ finding.replay.reproduced }} over {{ finding.replay.replays }} replay(s) on `{{ finding.replay.backend }}` |
| Deterministic | {{ finding.replay.deterministic }} |
{% endif %}
### Root cause

{{ finding.verdict.root_cause }}

### Evidence

{% if finding.classification -%}
- **Fault**: {{ finding.classification.fault_type }} ({{ finding.classification.access }}) at
  `{{ "0x%x"|format(finding.classification.fault_runtime_addr) }}`{% if finding.classification.fault_symbol %} in `{{ finding.classification.fault_symbol }}`{% endif %}.
- **Address shape**: near-null `{{ finding.classification.near_null }}`, wild `{{ finding.classification.wild }}`.
- **Attacker influence on the faulting address**: `{{ finding.classification.attacker_influenced }}`{% if finding.classification.influence_widths %} (matched at {{ finding.classification.influence_widths }}-byte widths){% endif %}.
{% endif -%}
{% if finding.trace -%}
- **Dynamic**: execution reached the fuzz entry: `{{ finding.trace.reached_fuzz_entry }}`.
{% endif -%}
{% if finding.context and finding.context.in_module_call_path -%}
- **Path into the fault** (chronological, not a call stack):
  `{{ finding.context.in_module_call_path|join(" -> ") }}`, faulting in
  `{{ finding.context.faulting_frame }}`.
{% endif -%}
{% if finding.context and not finding.context.is_faulting_frame and finding.context.function -%}
- **Note on the code below**: it is `{{ finding.context.function }}`, a **caller**
  on the fault path, not the function containing the faulting instruction. The
  fault is inside a library for which no decompilation is available.
{% endif %}
- **Signals used by triage**: {{ finding.verdict.signals_used|join(", ") }}
{% if finding.context and finding.context.pseudo_c %}
### Decompiled code (lossy -- not source)

```c
{{ finding.context.pseudo_c }}
```
{% endif %}
### Reproducing

```
wtf run --name {{ module }} --state <target>/state --backend=bochscpu \\
    --input {{ finding.verdict.reproducer_input_path or "<reproducer>" }}
```
{% endfor %}
---

## Scope of the analysis

| | |
|---|---|
| Target | {{ target }} |
| Fuzz entry | {{ entry }} |
| Execution backend | {{ backend }} |
| Crashes analysed | {{ crashes }} |
| Distinct buckets | {{ buckets }} |
| Confirmed | {{ findings | length }} |
| Discarded as false positives | {{ discarded }} |
"""


def render_report(
    findings: list[Finding],
    *,
    target: str,
    module: str,
    entry: str,
    backend: str = "bochscpu",
    crashes: int = 0,
    buckets: int = 0,
    discarded: int = 0,
    generated: str | None = None,
) -> str:
    """Render the advisory. Confirmed findings only -- caller filters."""
    for finding in findings:
        if finding.verdict.verdict != "confirmed":
            raise ValueError(
                f"{finding.verdict.bucket_id} has verdict "
                f"{finding.verdict.verdict!r}; only confirmed findings ship "
                f"(edges 42/43)"
            )

    # StrictUndefined: a typo in the template must fail loudly rather than render
    # a blank where a severity should be.
    env = Environment(undefined=StrictUndefined, trim_blocks=False, lstrip_blocks=False)
    # Dedup keys contain a literal `|` separator (`fault_type|module!function`),
    # which silently splits a Markdown table cell and shifts every column after
    # it. Escaping is not cosmetic here: a shifted row misattributes a severity.
    env.filters["cell"] = lambda value: str(value).replace("|", "\\|")
    template = env.from_string(_TEMPLATE)
    return template.render(
        findings=sorted(findings, key=lambda f: (f.severity_rank, -f.bucket.hit_count)),
        target=target,
        module=module,
        entry=entry,
        backend=backend,
        crashes=crashes,
        buckets=buckets,
        discarded=discarded,
        generated=generated
        or datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC"),
    )


def write_report(
    verdicts: list[TriageVerdict],
    *,
    buckets: dict[str, CrashBucket],
    out_dir: Path,
    target: str,
    module: str,
    entry: str,
    classifications: dict[str, Classification] | None = None,
    replays: dict[str, ReplayResult] | None = None,
    traces: dict[str, TraceRef] | None = None,
    contexts: dict[str, CrashContext] | None = None,
    crashes: int = 0,
    backend: str = "bochscpu",
    generated: str | None = None,
) -> tuple[Path, Path]:
    """Write the advisory and the discard log. Returns both paths."""
    out_dir.mkdir(parents=True, exist_ok=True)
    classifications = classifications or {}
    replays = replays or {}
    traces = traces or {}
    contexts = contexts or {}

    confirmed = [v for v in verdicts if v.verdict == "confirmed"]
    discarded = [v for v in verdicts if v.verdict != "confirmed"]

    findings = [
        Finding(
            verdict=verdict,
            bucket=buckets[verdict.bucket_id],
            classification=classifications.get(verdict.bucket_id),
            replay=replays.get(verdict.bucket_id),
            trace=traces.get(verdict.bucket_id),
            context=contexts.get(verdict.bucket_id),
        )
        for verdict in confirmed
        if verdict.bucket_id in buckets
    ]

    report_path = out_dir / "advisory.md"
    report_path.write_text(
        render_report(
            findings,
            target=target,
            module=module,
            entry=entry,
            backend=backend,
            crashes=crashes,
            buckets=len(buckets),
            discarded=len(discarded),
            generated=generated,
        ),
        encoding="utf-8",
    )

    # Kept for evaluation, not shipped (section 9). Deleting these would make a
    # triage regression invisible.
    discard_path = out_dir / "discarded.jsonl"
    with discard_path.open("w", encoding="utf-8") as fd:
        for verdict in discarded:
            fd.write(json.dumps(json.loads(verdict.model_dump_json())) + "\n")

    return report_path, discard_path
