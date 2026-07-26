"""Multi-signal crash triage with DSPy (CLAUDE.md CP9, edges 38-43).

**Terminology, and it matters.** This is **triage**: deciding whether a crash is a
real, interesting bug. It is *not* verification -- adjudicating a static finding
using source and a PoC -- and section 1 forbids calling it that. The project's
framing depends on the distinction: fuzzing is the right tool for discovery and
the wrong tool for verification, and mislabelling this stage creates a
contradiction the author's own paper would be used to attack.

Why DSPy
--------
Triage is structured classification plus extraction with an evaluable metric, so
the prompt can be optimised against labels instead of hand-tuned. Section 9 is
explicit that DSPy stays **triage-only** in v1: wrapping seed generation in it
would need the fuzzer run per candidate, which is far too slow to optimise
against.

The five signals, and why they stay separate
--------------------------------------------
1. ``dedup`` -- bucket id, hit count, and which key rung produced the bucket.
2. ``classification`` -- fault type and address, read vs write, near-null vs
   wild, attacker influence *with the widths it matched*.
3. ``replay`` -- reproduced, deterministic, on which backend.
4. ``symbolize_trace`` -- **dynamic**: the path actually executed.
5. ``reverse_engineer`` -- **static**: pseudo-C and the globals involved.

Signals 4 and 5 are handed over as separate fields on purpose. One says what ran,
the other what the code says; their errors are uncorrelated, and that
independence is the whole design (edges 41/41b). Section 10 lists collapsing them
into one blob, or letting any single signal decide, as anti-patterns -- so the
prompt asks for cross-checking explicitly, and a verdict that cites one signal
alone is reported as low confidence.

What triage never receives
--------------------------
A sanitizer report. There is no ASAN (section 2), so the prompt is written for a
binary-only oracle: observable faults only, and silent memory corruption out of
scope. It also never receives source -- pseudo-C is lossy, with invented names and
inferred types.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from analysis.classify import Classification
from analysis.reverse import CrashContext
from arch.contracts import (
    TRIAGE_SIGNALS,
    CrashBucket,
    ReplayResult,
    TraceRef,
    TriageVerdict,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_LLM_CONFIG = REPO_ROOT / "config" / "llm.yaml"

__all__ = [
    "TriageError",
    "SignalBundle",
    "TriageProgram",
    "configure_dspy",
    "render_signals",
]


class TriageError(RuntimeError):
    pass


@dataclass
class SignalBundle:
    """The five signals for one bucket, plus where its reproducer lives."""

    bucket: CrashBucket
    classification: Classification
    replay: ReplayResult
    trace: TraceRef | None = None
    context: CrashContext | None = None
    reproducer_path: str = ""

    @property
    def available(self) -> list[str]:
        present = ["dedup", "classification", "replay"]
        if self.trace is not None:
            present.append("symbolize_trace")
        if self.context is not None:
            present.append("reverse_engineer")
        return present

    @property
    def missing(self) -> list[str]:
        return [s for s in TRIAGE_SIGNALS if s not in self.available]


def _resolve(config: dict, repo_root: Path = REPO_ROOT, prefer: str | None = None):
    """Which provider and key to use, via the client's own resolver.

    Delegated rather than reimplemented. This function used to duplicate the
    key-reading logic -- including the utf-8-sig BOM handling -- and a duplicate
    of that kind stays correct only until one copy is fixed.
    """
    from llm.client import LlmError, resolve_provider

    try:
        return resolve_provider(config, repo_root=repo_root, prefer=prefer)
    except LlmError as exc:
        raise TriageError(str(exc)) from exc


def configure_dspy(
    *,
    role: str = "triage",
    config_path: Path = DEFAULT_LLM_CONFIG,
    repo_root: Path = REPO_ROOT,
    provider: str | None = None,
) -> Any:
    """Point DSPy at the active provider for ``role``, and return the LM.

    Model, base URL and parameters all come from ``config/llm.yaml`` -- section 10
    forbids hardcoding any of them, and DSPy is no exception just because it
    brings its own client. The role is a role, never a model name.

    DSPy reaches the model through litellm, which needs a provider prefix on the
    model string; the two kinds this project configures need different ones, and
    two other things differ with them:

    * ``openai_compatible`` -> ``openai/<model>`` with an explicit ``api_base``,
      so litellm uses the OpenAI wire format against a custom URL instead of
      trying to infer a provider from the model name.
    * ``anthropic`` -> ``anthropic/<model>``, no ``api_base``, and **no
      ``temperature``** -- sending one is an HTTP 400 on the current Claude
      models, so it is dropped here exactly as llm/providers.py drops it.
    """
    import dspy

    config = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    roles = config["roles"]
    if role not in roles:
        raise TriageError(f"unknown role {role!r}; configured: {sorted(roles)}")

    resolved = _resolve(config, repo_root, prefer=provider)

    role_config = dict(roles[role])
    role_config.pop("why", None)
    models = role_config.pop("models", None) or {}
    model = models.get(resolved.name)
    if not model:
        raise TriageError(
            f"role {role!r} has no model configured for provider "
            f"{resolved.name!r}; it maps {sorted(k for k, v in models.items() if v)}"
        )

    excluded = set(config.get("excluded_models") or [])
    if model in excluded:
        raise TriageError(f"role {role!r} routes to excluded model {model!r}")

    kwargs: dict[str, Any] = {
        "api_key": resolved.api_key,
        "model_type": "chat",
        "max_tokens": role_config.get("max_tokens", 16384),
        "num_retries": int(resolved.config.get("max_retries", 3)),
    }
    if resolved.kind == "anthropic":
        target = f"anthropic/{model}"
        # temperature deliberately absent -- see the docstring.
        if resolved.config.get("base_url"):
            kwargs["api_base"] = resolved.config["base_url"]
    else:
        target = f"openai/{model}"
        kwargs["api_base"] = resolved.config["base_url"]
        kwargs["temperature"] = role_config.get("temperature", 0.0)

    lm = dspy.LM(target, **kwargs)
    dspy.configure(lm=lm)
    return lm


def format_static_addr(addr: int | None) -> str:
    """A static address for a prompt, or a statement that there is not one.

    The absent case is spelled out rather than shown as `0x0`: the model is being
    asked to reason about where a fault happened, and an address it cannot
    distinguish from "we could not attribute this" is worse than a sentence.
    """
    if addr is None:
        return "not attributable to the target module"
    return f"{addr:#x}"


def render_signals(bundle: SignalBundle) -> dict[str, str]:
    """One string per signal, kept in separate fields.

    Never merged into a single blob (section 10). Absent signals are rendered as
    an explicit statement of absence: a triage prompt that silently omits signal 4
    invites reasoning as though the dynamic evidence agreed.
    """
    bucket = bundle.bucket
    dedup = (
        f"bucket {bucket.bucket_id}\n"
        f"hit_count: {bucket.hit_count} (crashes merged into this bucket)\n"
        f"dedup key rung: {bucket.key_kind} -- {bucket.key_detail}\n"
        f"NOTE on the rung: 'stack_hash' is the most precise; 'fault_function' "
        f"groups every fault inside one function; 'fault_module' cannot collapse "
        f"within a function; 'fault_type' merges aggressively and may well have "
        f"merged unrelated bugs. Weigh hit_count accordingly.\n"
        f"reproducer size: {len(bucket.representative.input_bytes)} bytes"
    )

    c = bundle.classification
    classification = (
        f"fault type: {c.fault_type}\n"
        f"access: {c.access}\n"
        f"fault address: {c.fault_runtime_addr:#x} (runtime), "
        # `:#x` on None is a TypeError, so this is rendered explicitly rather
        # than formatted. And what the model is told changed with it: "0 means
        # not in the target module" asked it to decode a sentinel, which is the
        # same demand the type change removed from our own code (D-068).
        f"{format_static_addr(c.fault_static_addr)} (static)\n"
        f"module: {c.fault_module} symbol: {c.fault_symbol}\n"
        f"near_null: {c.near_null}   wild: {c.wild}\n"
        f"attacker_influenced: {c.attacker_influenced} "
        f"at widths {c.influence_widths} bytes, offsets {c.influence_offsets[:8]}\n"
        f"faulting instruction: {c.faulting_instruction} "
        f"(source: {c.disasm_source})\n"
        f"registers available: {c.registers_available}\n"
        f"limits and caveats recorded by the classifier:\n  - "
        + "\n  - ".join(c.notes or ["none"])
    )

    r = bundle.replay
    replay = (
        f"reproduced: {r.reproduced}\n"
        f"deterministic: {r.deterministic}\n"
        f"replays: {r.replays}\n"
        f"backend: {r.backend} "
        f"({'fully deterministic' if r.backend == 'bochscpu' else 'NOT deterministic by default'})\n"
        f"notes: {r.notes}"
    )

    if bundle.trace is None:
        trace = (
            "NOT AVAILABLE. No execution trace was produced for this bucket, so "
            "there is no dynamic evidence. Do not infer that the dynamic evidence "
            "agrees with the static evidence."
        )
    else:
        t = bundle.trace
        trace = (
            f"trace type: {t.trace_type}\n"
            f"reached the fuzz entry: {t.reached_fuzz_entry} "
            f"(False means execution never entered the target parser, so this "
            f"crash says nothing about the target)\n"
        )
        if bundle.context is not None and bundle.context.in_module_call_path:
            trace += (
                f"target-module functions executed before the fault, in order "
                f"(chronological, NOT a call stack): "
                f"{bundle.context.in_module_call_path}\n"
                f"faulting frame: {bundle.context.faulting_frame}"
            )

    if bundle.context is None:
        reverse = (
            "NOT AVAILABLE. No static context was assembled, so there is no "
            "pseudo-C for this crash."
        )
    else:
        x = bundle.context
        reverse = (
            f"context frame: {x.context_frame} "
            f"(is this the faulting instruction's own function? "
            f"{x.is_faulting_frame})\n"
            f"faulting frame: {x.faulting_frame}\n"
            f"pseudo-C source: {x.pseudo_c_source}\n"
            f"IMPORTANT: pseudo-C is DECOMPILER OUTPUT, not source. Names may be "
            f"invented, types are inferred, inlining is flattened.\n"
            f"{x.globals_touched}"
            f"--- pseudo-C ---\n{x.pseudo_c or '(none)'}\n"
            f"caveats recorded while assembling this:\n  - "
            + "\n  - ".join(x.notes or ["none"])
        )

    return {
        "dedup": dedup,
        "classification": classification,
        "replay": replay,
        "symbolize_trace": trace,
        "reverse_engineer": reverse,
    }


def _build_signature():
    """The DSPy signature. Built lazily so importing this module needs no dspy."""
    import dspy

    class TriageSignature(dspy.Signature):
        """Decide whether a crash found by a binary-only snapshot fuzzer is a real bug.

        You are triaging, not verifying: the question is whether this is a real,
        interesting bug worth a human's time, not whether a claimed vulnerability
        can be proven.

        THE ACCESS LEVEL. There is no sanitizer. The oracle observes faults only --
        access violations, aborts, illegal instructions, timeouts. Memory
        corruption that does not fault is invisible to it, so the ABSENCE of a
        crash is never evidence of safety. You have no source: the pseudo-C is
        decompiler output with invented names and inferred types.

        HOW TO WEIGH THE FIVE SIGNALS. They are independent and no single one
        decides. Cross-check them:
        - A deterministic near-null READ on a path that does not consume input is
          usually an allocation-failure or uninitialised-state path, not a bug.
        - An out-of-bounds WRITE is materially more serious than a read, even at
          the same address, because it corrupts state rather than leaking it.
        - Attacker influence matched only at 2 bytes is a coincidence in most
          binary inputs. Influence at 8 bytes is strong.
        - A crash that did not reproduce is NOT automatically benign; it may
          depend on state the snapshot does not carry, or on backend
          nondeterminism if the backend was not bochscpu.
        - If the trace says execution never reached the fuzz entry, the crash is
          about the harness, not the target.
        - If the static context says the pseudo-C is a CALLER rather than the
          faulting instruction's own function, reason about the caller's use of
          the callee -- do not treat the pseudo-C as the fault site.
        - A coarse dedup rung means hit_count may be aggregating unrelated bugs,
          so a high count is weaker evidence than it looks.

        DISTINGUISH DoS FROM RCE. A crash that reliably kills the process is
        already serious and is 'dos'. Only say 'possible_rce' when the evidence
        shows attacker-influenced control over what is written or where.

        signals_used must name every signal you actually relied on, from:
        dedup, classification, replay, symbolize_trace, reverse_engineer.
        """

        dedup: str = dspy.InputField(desc="signal 1: bucket identity and hit count")
        classification: str = dspy.InputField(
            desc="signal 2: fault type, address, access, attacker influence"
        )
        replay: str = dspy.InputField(
            desc="signal 3: reproduced and deterministic, and on which backend"
        )
        symbolize_trace: str = dspy.InputField(
            desc="signal 4: DYNAMIC -- the path actually executed"
        )
        reverse_engineer: str = dspy.InputField(
            desc="signal 5: STATIC -- pseudo-C and globals of the relevant function"
        )

        verdict: str = dspy.OutputField(desc="confirmed or false_positive")
        confidence: float = dspy.OutputField(desc="0.0 to 1.0")
        cwe_guess: str = dspy.OutputField(
            desc="most likely CWE id, e.g. CWE-125, or 'none'"
        )
        exploitability: str = dspy.OutputField(
            desc="dos, info_leak, possible_rce, or unknown"
        )
        root_cause: str = dspy.OutputField(
            desc="two or three sentences on the mechanism, naming the evidence"
        )
        signals_used: str = dspy.OutputField(
            desc="comma-separated signal names actually relied on"
        )

    return TriageSignature


_VERDICTS = {"confirmed", "false_positive"}
_EXPLOITABILITY = {"dos", "info_leak", "possible_rce", "unknown"}


class TriageProgram:
    """DSPy program wrapping the triage signature.

    Kept as a thin class rather than a bare module function so that an optimised
    version (CP9's DSPy compilation) can be swapped in without changing callers.
    """

    def __init__(self, *, use_cot: bool = True) -> None:
        import dspy

        signature = _build_signature()
        self.module = (
            dspy.ChainOfThought(signature) if use_cot else dspy.Predict(signature)
        )

    def __call__(self, bundle: SignalBundle) -> TriageVerdict:
        rendered = render_signals(bundle)
        prediction = self.module(**rendered)
        return self.to_verdict(prediction, bundle)

    @staticmethod
    def to_verdict(prediction: Any, bundle: SignalBundle) -> TriageVerdict:
        """Coerce a prediction into the contract, refusing to invent fields.

        An out-of-range value becomes the explicit unknown rather than being
        clamped to something that reads as a decision.
        """
        raw_verdict = str(getattr(prediction, "verdict", "")).strip().lower()
        if raw_verdict not in _VERDICTS:
            # Anything unparseable is treated as a false positive: over-reporting
            # findings is the failure mode that wastes a human's time, and a
            # model that could not answer the question has not made a case.
            raw_verdict = "false_positive"

        exploitability = str(getattr(prediction, "exploitability", "")).strip().lower()
        if exploitability not in _EXPLOITABILITY:
            exploitability = "unknown"

        try:
            confidence = float(getattr(prediction, "confidence", 0.0))
        except (TypeError, ValueError):
            confidence = 0.0
        confidence = min(max(confidence, 0.0), 1.0)

        cwe = str(getattr(prediction, "cwe_guess", "") or "").strip()
        if cwe.lower() in {"", "none", "n/a", "unknown"}:
            cwe = None

        claimed = [
            token.strip()
            for token in str(getattr(prediction, "signals_used", "")).split(",")
            if token.strip()
        ]
        # Only credit signals that were actually supplied. A model claiming to
        # have used the trace when no trace existed must not be recorded as
        # having done so -- that would make signals_used unfalsifiable.
        used = [s for s in claimed if s in bundle.available]

        return TriageVerdict(
            bucket_id=bundle.bucket.bucket_id,
            verdict=raw_verdict,
            confidence=confidence,
            cwe_guess=cwe,
            exploitability=exploitability,
            root_cause=str(getattr(prediction, "root_cause", "")).strip(),
            signals_used=used or bundle.available,
            reproducer_input_path=bundle.reproducer_path,
        )


def triage_metric(example: Any, prediction: Any, trace: Any = None) -> float:
    """DSPy metric: verdict correctness, with partial credit for the extras.

    The verdict dominates because it is the decision that ships or discards a
    finding. CWE and exploitability are worth something but a correct verdict with
    a wrong CWE is far better than the reverse.
    """
    expected = str(getattr(example, "label", "")).strip().lower()
    got = str(getattr(prediction, "verdict", "")).strip().lower()
    if got not in _VERDICTS:
        got = "false_positive"

    if expected != got:
        return 0.0

    score = 0.7
    expected_exploit = str(getattr(example, "expected_exploitability", "")).lower()
    if expected_exploit and expected_exploit == str(
        getattr(prediction, "exploitability", "")
    ).strip().lower():
        score += 0.15

    expected_cwe = (getattr(example, "expected_cwe", "") or "").upper()
    got_cwe = str(getattr(prediction, "cwe_guess", "") or "").upper()
    if expected_cwe and expected_cwe in got_cwe:
        score += 0.15
    return score
