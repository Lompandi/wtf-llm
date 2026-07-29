"""Role-routed LLM client over several providers (CLAUDE.md CP5, section 7).

Takes a **role**, never a model name (section 7.2), so models swap in
`config/llm.yaml` without touching code. The provider is chosen the same way:
**whichever provider's API key is present wins**, in the order `providers` lists
them, so the same checkout runs against the NCHC endpoint, the Anthropic
Messages API, or OpenAI with no edit and no flag.

`resolve_provider` is the one function that knows the config's shape. Every other
module asks it rather than reading `config["endpoint"][...]` itself -- four
modules independently reaching into the same keys is how a config change breaks
three of them and nobody notices until the fourth runs.

Per-provider wire differences live in `llm/providers.py`. What stays here is what
is the same regardless of provider: role routing, the budget cap, the usage log,
and the retry policy.

Three behaviours of the NCHC endpoint drove that retry policy, all measured
rather than assumed (docs/DEVIATIONS.md D-030):

* **`content` can be `null` on HTTP 200.** ``gemma-4-12b`` and ``gemma-4-26b``
  are reasoning models whose ``reasoning_content`` is billed against
  ``max_tokens``. Exhaust the budget and the response is a perfectly valid 200
  with a null content and ``finish_reason: "length"``. Treated here as a
  retryable error with a larger budget -- never as an empty answer, which is how
  it would otherwise surface: "the LLM had no suggestions".
* **Reasoning is slow.** 18-22s for those two models against ~2s for
  nemotron-cascade-2-30b on the same task, so the timeout is generous.
* **Latency varies by an order of magnitude between models**, which matters for
  the slow clock's responsiveness but never for the fast loop -- RULE 1.

The first of those generalises rather than being NCHC-specific: Anthropic has the
same failure under a different name, because thinking is on by default and billed
against ``max_tokens``, so an exhausted budget gives ``stop_reason:
"max_tokens"`` with truncated or absent text. Both providers report it through
``RawCompletion.truncated`` and the doubling retry below covers both.

**This module is only ever called from the slow clock.** RULE 1 and section 12.2:
never from the fast loop, and never from the master. `tests/gates/test_cp4.py`
asserts no fast-path module imports it.
"""

from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from collections.abc import Callable
from typing import Any, TypeVar

import yaml
from pydantic import BaseModel, ValidationError

from llm.providers import Provider, ProviderError, ProviderRefusal, build_provider

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONFIG = REPO_ROOT / "config" / "llm.yaml"

M = TypeVar("M", bound=BaseModel)

__all__ = [
    "LlmError",
    "BudgetExceeded",
    "EmptyCompletion",
    "Refused",
    "Completion",
    "LlmClient",
    "ResolvedProvider",
    "resolve_provider",
    "available_providers",
    "PROVIDER_ENV",
]

# Set to a provider name to override key-order precedence. Read here rather than
# only in the CLIs, so a library caller gets the same behaviour as a command line.
PROVIDER_ENV = "SNAPFUZZ_LLM_PROVIDER"

# ```json ... ``` or ``` ... ```
_FENCE_RE = re.compile(r"^\s*```(?:[a-zA-Z0-9_+-]*)\s*\n?|\n?\s*```\s*$")


class LlmError(RuntimeError):
    pass


class BudgetExceeded(LlmError):
    """Raised instead of spending past the configured cap (section 7.3)."""


class EmptyCompletion(LlmError):
    """HTTP 200 but no usable content -- see D-030. Retryable."""


class Refused(LlmError):
    """The provider declined on policy grounds. NOT retryable.

    Separate from every other failure for two reasons: retrying it burns the
    allocation to no effect, and a caller may need to act on it. "No verdict
    could be obtained" is a different outcome from "the crash is benign", and
    collapsing the two would silently discard findings -- which is exactly the
    class of failure this project's gates exist to catch.
    """

    def __init__(self, message: str, *, category: str | None = None) -> None:
        super().__init__(message)
        self.category = category


@dataclass(frozen=True)
class Completion:
    role: str
    model: str
    content: str
    reasoning: str | None
    finish_reason: str | None
    prompt_tokens: int
    completion_tokens: int
    latency_s: float
    attempts: int
    # Which provider served it, and which model actually answered. `served_model`
    # differs from `model` when a policy decline was recovered by a fallback; a
    # usage log naming only the requested model would be wrong about the spend.
    provider: str = ""
    served_model: str | None = None

    @property
    def total_tokens(self) -> int:
        return self.prompt_tokens + self.completion_tokens


def strip_code_fences(text: str) -> str:
    """Remove a wrapping ``` fence. CP5 requires this before validation."""
    out = text.strip()
    # Applied twice: the opening and closing fences are separate matches.
    for _ in range(2):
        out = _FENCE_RE.sub("", out, count=1).strip()
    return out


def extract_json_object(text: str) -> str:
    """Best-effort isolation of a JSON object from a chatty reply.

    Used only after a strict parse fails. Models sometimes prepend a sentence
    despite being told not to, and re-prompting for that is a waste of the
    allocation when the object is right there.
    """
    cleaned = strip_code_fences(text)
    try:
        json.loads(cleaned)
        return cleaned
    except json.JSONDecodeError:
        pass

    start = cleaned.find("{")
    end = cleaned.rfind("}")
    if start != -1 and end > start:
        return cleaned[start : end + 1]

    start, end = cleaned.find("["), cleaned.rfind("]")
    if start != -1 and end > start:
        return cleaned[start : end + 1]

    return cleaned


# --- provider resolution --------------------------------------------------
#
# The single place that knows the config's shape. Consumed by llm/client.py
# itself, analysis/triage.py (DSPy), orchestrator/pipeline.py (pre-flight) and
# tools/bootstrap.py (setup report).


@dataclass(frozen=True)
class ResolvedProvider:
    name: str
    config: dict[str, Any]
    api_key: str

    @property
    def kind(self) -> str:
        return self.config["kind"]


def _read_dotenv(repo_root: Path, key: str) -> str | None:
    """Read one key from a gitignored .env, so a shell need not export it.

    Decoded as ``utf-8-sig``: Windows PowerShell 5.1's ``Set-Content -Encoding
    utf8`` writes a BOM, which would otherwise make the first key in the file
    read as ``\\ufeffSNAPFUZZ_LLM_API_KEY`` and never match.
    """
    path = repo_root / ".env"
    if not path.exists():
        return None
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, value = line.split("=", 1)
        if name.strip() == key:
            return value.strip().strip("\"'")
    return None


def _provider_key(
    name: str, provider: dict[str, Any], repo_root: Path
) -> str | None:
    """The key for one provider, from the environment then `.env`.

    An inline `api_key` is refused rather than used. Section 10 forbids it and a
    gate test enforces it, but the check belongs here too: this is the function
    that would otherwise silently honour a pasted token and get it committed.
    """
    if provider.get("api_key"):
        raise LlmError(
            f"provider {name!r} contains an inline api_key in config/llm.yaml. "
            f"The token must come from the environment (section 7.1, section 10)."
        )
    env_var = provider.get("api_key_env")
    if not env_var:
        raise LlmError(f"provider {name!r} declares no api_key_env")
    return os.environ.get(env_var) or _read_dotenv(repo_root, env_var)


def available_providers(
    config: dict[str, Any], *, repo_root: Path = REPO_ROOT
) -> list[str]:
    """Provider names whose key resolves, in config order.

    Used by the setup report and the pipeline's pre-flight check so they can say
    which providers are usable instead of naming one hardcoded variable.
    """
    providers = config.get("providers") or {}
    found: list[str] = []
    for name, provider in providers.items():
        try:
            if _provider_key(name, provider, repo_root):
                found.append(name)
        except LlmError:
            # A misconfigured provider is not an available one. The specific
            # complaint is raised by resolve_provider, which is where a caller
            # asking to USE it will see it.
            continue
    return found


def resolve_provider(
    config: dict[str, Any],
    *,
    repo_root: Path = REPO_ROOT,
    prefer: str | None = None,
) -> ResolvedProvider:
    """Pick the provider: explicit argument, then env var, then key order.

    Config is consulted LAST in the same sense as everywhere else in this
    project (section 14.1): an explicit choice beats an environment variable,
    which beats the committed ordering.
    """
    providers = config.get("providers") or {}
    if not providers:
        raise LlmError(
            "config/llm.yaml has no `providers` block. It used to have a single "
            "`endpoint`; see llm/client.py for the shape."
        )

    requested = prefer or os.environ.get(PROVIDER_ENV) or None
    if requested:
        if requested not in providers:
            raise LlmError(
                f"provider {requested!r} is not configured; available: "
                f"{sorted(providers)}"
            )
        key = _provider_key(requested, providers[requested], repo_root)
        if not key:
            env_var = providers[requested]["api_key_env"]
            raise LlmError(
                f"provider {requested!r} was requested explicitly but "
                f"{env_var} is set neither in the environment nor in a "
                f"gitignored .env at the repo root"
            )
        return ResolvedProvider(requested, providers[requested], key)

    for name, provider in providers.items():
        key = _provider_key(name, provider, repo_root)
        if key:
            return ResolvedProvider(name, provider, key)

    wanted = ", ".join(
        str((p or {}).get("api_key_env")) for p in providers.values()
    )
    raise LlmError(
        f"no LLM API key: set one of [{wanted}] in the environment or in a "
        f"gitignored .env at the repo root"
    )


@dataclass
class LlmClient:
    """Role-routed client with usage logging and a hard budget cap."""

    config: dict[str, Any]
    api_key: str
    usage_log: Path
    provider_name: str = "nchc"
    provider_config: dict[str, Any] = field(default_factory=dict)
    calls_made: int = field(default=0, init=False)
    completion_tokens_spent: int = field(default=0, init=False)
    _provider: Provider | None = field(default=None, init=False)

    # --- construction ----------------------------------------------------

    @classmethod
    def from_config(
        cls,
        path: Path = DEFAULT_CONFIG,
        *,
        api_key: str | None = None,
        repo_root: Path = REPO_ROOT,
        provider: str | None = None,
    ) -> LlmClient:
        config = yaml.safe_load(path.read_text(encoding="utf-8"))
        resolved = resolve_provider(config, repo_root=repo_root, prefer=provider)

        usage_log = repo_root / config["budget"]["usage_log"]
        return cls(
            config=config,
            api_key=api_key or resolved.api_key,
            usage_log=usage_log,
            provider_name=resolved.name,
            provider_config=resolved.config,
        )

    def __enter__(self) -> LlmClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def close(self) -> None:
        if self._provider is not None:
            self._provider.close()
            self._provider = None

    def _backend(self) -> Provider:
        if self._provider is None:
            self._provider = build_provider(
                self.provider_name, self.provider_config, self.api_key
            )
        return self._provider

    # --- routing ---------------------------------------------------------

    @property
    def roles(self) -> list[str]:
        return sorted(self.config["roles"])

    def model_for(self, role: str, *, provider: str | None = None) -> str:
        roles = self.config["roles"]
        if role not in roles:
            raise LlmError(f"unknown role {role!r}; configured: {sorted(roles)}")

        name = provider or self.provider_name
        models = roles[role].get("models") or {}
        if name not in models:
            raise LlmError(
                f"role {role!r} has no model configured for provider {name!r}; "
                f"it maps {sorted(models)}. Add it to config/llm.yaml -- there is "
                f"deliberately no default, because a model nobody chose is how a "
                f"campaign gets attributed to the wrong one (D-056)."
            )
        model = models[name]
        if not model:
            raise LlmError(
                f"role {role!r} maps provider {name!r} to null. Set it to a model "
                f"id confirmed against that provider's model list."
            )

        excluded = set(self.config.get("excluded_models") or [])
        if model in excluded:
            # llama-guard-3-8b is a safety classifier, not a chat model
            # (section 7.2). Wiring it in would produce nonsense verdicts.
            raise LlmError(
                f"role {role!r} is routed to {model!r}, which is excluded from "
                f"this pipeline"
            )
        return model

    def _role_params(self, role: str) -> dict[str, Any]:
        cfg = dict(self.config["roles"][role])
        cfg.pop("why", None)
        cfg.pop("model", None)
        cfg.pop("models", None)
        return cfg

    # --- budget ----------------------------------------------------------

    def _check_budget(self) -> None:
        budget = self.config.get("budget") or {}
        max_calls = budget.get("max_total_calls")
        max_tokens = budget.get("max_total_completion_tokens")

        if max_calls is not None and self.calls_made >= max_calls:
            raise BudgetExceeded(
                f"refusing call {self.calls_made + 1}: budget.max_total_calls is "
                f"{max_calls}. Raise it deliberately in config/llm.yaml."
            )
        if max_tokens is not None and self.completion_tokens_spent >= max_tokens:
            raise BudgetExceeded(
                f"refusing call: {self.completion_tokens_spent} completion tokens "
                f"spent against a cap of {max_tokens}."
            )

    # --- the call --------------------------------------------------------

    def complete(
        self,
        role: str,
        prompt: str,
        *,
        system: str | None = None,
        max_tokens: int | None = None,
        temperature: float | None = None,
        json_schema: dict[str, Any] | None = None,
    ) -> Completion:
        """One completion for ``role``, with bounded retry.

        ``json_schema`` is used only on providers that enforce it natively; on the
        others it is ignored and `complete_json` asks for JSON in the prompt
        instead. That asymmetry is deliberate -- using each provider's real
        mechanism beats emulating the weakest one everywhere.
        """
        provider = self._backend()
        handling = self.config.get("response_handling") or {}
        model = self.model_for(role)
        params = self._role_params(role)
        if temperature is not None:
            params["temperature"] = temperature

        budget_tokens = int(max_tokens or params.get("max_tokens", 4096))
        max_retries = int(self.provider_config.get("max_retries", 3))
        backoff = float(self.provider_config.get("retry_backoff_s", 2.0))
        # Rate limits get their own, much larger schedule: 20s, 40s, 60s by default.
        # Bounded, because a caller waiting on a build stage would rather be told the
        # endpoint is saturated than block indefinitely.
        rate_limit_backoff = float(
            self.provider_config.get("rate_limit_backoff_s", 20.0)
        )
        rate_limit_max_s = float(self.provider_config.get("rate_limit_max_wait_s", 60.0))
        last_error: Exception | None = None

        for attempt in range(1, max_retries + 1):
            self._check_budget()
            started = time.time()
            try:
                if json_schema is not None and provider.supports_native_json:
                    raw = provider.complete_json(
                        model=model,
                        prompt=prompt,
                        system=system,
                        max_tokens=budget_tokens,
                        params=params,
                        schema=json_schema,
                    )
                else:
                    raw = provider.complete(
                        model=model,
                        prompt=prompt,
                        system=system,
                        max_tokens=budget_tokens,
                        params=params,
                    )
            except ProviderRefusal as exc:
                # NOT retried, and not swallowed. Logged first so the refusal is
                # visible in the usage log rather than only in a traceback.
                self._log_usage(
                    role, model, 0, 0, time.time() - started, attempt,
                    f"refusal: {exc}", refusal_category=exc.category,
                )
                raise Refused(str(exc), category=exc.category) from exc
            except ProviderError as exc:
                last_error = exc
                self._log_usage(
                    role, model, 0, 0, time.time() - started, attempt, str(exc)
                )
                if attempt == max_retries:
                    break
                # A RATE LIMIT is not a failure to retry the same way as a 500. The
                # server is saying "come back later", so the wait has to be long enough
                # to matter: `backoff * attempt` is 2s then 4s, which against a shared
                # endpoint burns every attempt inside the window that is throttling and
                # reports a hard failure for something that only needed waiting (D-075).
                if getattr(exc, "rate_limited", False):
                    wait = exc.retry_after_s or (rate_limit_backoff * attempt)
                    wait = min(wait, rate_limit_max_s)
                    print(
                        f"  [rate limited] {model} -- waiting {wait:.0f}s "
                        f"(attempt {attempt}/{max_retries})"
                    )
                    time.sleep(wait)
                    continue
                time.sleep(backoff * attempt)
                continue

            latency = time.time() - started
            self.calls_made += 1
            self.completion_tokens_spent += raw.completion_tokens
            self._log_usage(
                role,
                model,
                raw.prompt_tokens,
                raw.completion_tokens,
                latency,
                attempt,
                None,
                finish_reason=raw.finish_reason,
                max_tokens=budget_tokens,
                reasoning_chars=len(raw.reasoning or ""),
                served_model=raw.served_model,
            )

            # D-030 on the NCHC path, `stop_reason: "max_tokens"` on Anthropic:
            # the budget went on reasoning and the answer is absent or cut off.
            # Retry with a bigger budget rather than reporting "no answer", which
            # is what makes this failure mode invisible.
            truncated = raw.truncated and handling.get(
                "treat_length_finish_as_error", True
            )
            if not raw.content or truncated:
                last_error = EmptyCompletion(
                    f"{model} returned finish_reason={raw.finish_reason!r} with "
                    f"{len(raw.reasoning or '')} reasoning chars and "
                    f"{'no' if not raw.content else 'truncated'} content at "
                    f"max_tokens={budget_tokens}"
                )
                if attempt == max_retries:
                    break
                budget_tokens *= 2  # reasoning consumed the budget
                continue

            return Completion(
                role=role,
                model=model,
                content=raw.content,
                reasoning=raw.reasoning,
                finish_reason=raw.finish_reason,
                prompt_tokens=raw.prompt_tokens,
                completion_tokens=raw.completion_tokens,
                latency_s=latency,
                attempts=attempt,
                provider=self.provider_name,
                served_model=raw.served_model,
            )

        raise LlmError(
            f"role {role!r} on provider {self.provider_name!r} failed after "
            f"{max_retries} attempts (final max_tokens={budget_tokens}): "
            f"{last_error}"
        ) from last_error

    def complete_json(
        self,
        role: str,
        prompt: str,
        model_cls: type[M],
        *,
        system: str | None = None,
        max_tokens: int | None = None,
        retries: int = 1,
        coerce: Callable[[dict], dict] | None = None,
    ) -> M:
        """Structured output, validated against ``model_cls`` (CP5).

        Two paths, because the providers differ in kind and not only in degree:

        * **Native** (Anthropic) -- the schema goes on the request and the API
          enforces it. No JSON-only instruction, no fences to strip.
        * **Prompted** (OpenAI-compatible) -- the schema is described in the
          prompt, and the reply is de-fenced before validation.

        Both then validate and retry once, feeding the error back. That retry
        matters on the native path too: a `max_tokens` stop still yields
        truncated JSON, which is schema-shaped right up until it is cut off.
        """
        schema = model_cls.model_json_schema()
        native = self._backend().supports_native_json

        if native:
            base_prompt = prompt
        else:
            # Hand the model the actual schema rather than describing the fields
            # in prose. Without it, models invent plausible neighbouring names --
            # measured: `memcpy_offset` for `length_offset`, and a required field
            # simply omitted -- and the retry cannot recover because it still does
            # not know what the names are supposed to be.
            instruction = (
                "Respond with a single JSON object and nothing else: no prose, no "
                "explanation, no markdown code fences.\n"
                "The object MUST conform to this JSON Schema, using exactly these "
                f"property names:\n{json.dumps(schema, separators=(',', ':'))}"
            )
            base_prompt = f"{prompt}\n\n{instruction}"

        full_prompt = base_prompt
        last_error: Exception | None = None

        for _ in range(retries + 1):
            completion = self.complete(
                role,
                full_prompt,
                system=system,
                max_tokens=max_tokens,
                json_schema=schema,
            )
            candidate = extract_json_object(completion.content)
            try:
                # `coerce` runs BEFORE validation so a caller can enforce an invariant
                # rather than ask for it. The distinction that decides what belongs there:
                # a schema INVARIANT has exactly one correct value, so requesting it wastes
                # a round-trip and sometimes never converges -- `input_struct` retried
                # twice on "field 'payload' is variable-length bytes and must not have a
                # fixed ctype" with the rule stated plainly in the prompt. A JUDGEMENT
                # does not belong here, because silently overwriting one hides a
                # disagreement worth seeing.
                if coerce is not None:
                    payload = json.loads(candidate)
                    if isinstance(payload, dict):
                        payload = coerce(payload)
                    return model_cls.model_validate(payload)
                return model_cls.model_validate_json(candidate)
            except (ValidationError, ValueError) as exc:
                last_error = exc
                full_prompt = (
                    f"{base_prompt}\n\n"
                    f"Your previous reply could not be parsed as "
                    f"{model_cls.__name__}. The error was:\n{exc}\n"
                    f"Return corrected JSON."
                )

        raise LlmError(
            f"role {role!r} did not produce valid {model_cls.__name__} after "
            f"{retries + 1} attempts"
        ) from last_error

    # --- usage log -------------------------------------------------------

    def _log_usage(
        self,
        role: str,
        model: str,
        prompt_tokens: int,
        completion_tokens: int,
        latency_s: float,
        attempt: int,
        error: str | None,
        **extra: Any,
    ) -> None:
        """Append one record per call (section 7.3), including failures.

        Failures are logged too: an allocation burned on retries that never
        produced an answer is exactly what this log exists to make visible.
        """
        self.usage_log.parent.mkdir(parents=True, exist_ok=True)
        record = {
            "ts": time.time(),
            "provider": self.provider_name,
            "role": role,
            "model": model,
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "latency_s": round(latency_s, 3),
            "attempt": attempt,
            "error": error,
            "cumulative_calls": self.calls_made,
            "cumulative_completion_tokens": self.completion_tokens_spent,
            **extra,
        }
        with self.usage_log.open("a", encoding="utf-8") as fd:
            fd.write(json.dumps(record) + "\n")
