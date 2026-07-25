"""OpenAI-compatible LLM client with role routing (CLAUDE.md CP5, section 7).

Takes a **role**, never a model name (section 7.2), so models swap in
`config/llm.yaml` without touching code.

Three behaviours of this endpoint drove the design, all measured rather than
assumed (docs/DEVIATIONS.md D-030):

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
from typing import Any, TypeVar

import httpx
import yaml
from pydantic import BaseModel, ValidationError

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONFIG = REPO_ROOT / "config" / "llm.yaml"

M = TypeVar("M", bound=BaseModel)

__all__ = [
    "LlmError",
    "BudgetExceeded",
    "EmptyCompletion",
    "Completion",
    "LlmClient",
]

# ```json ... ``` or ``` ... ```
_FENCE_RE = re.compile(r"^\s*```(?:[a-zA-Z0-9_+-]*)\s*\n?|\n?\s*```\s*$")


class LlmError(RuntimeError):
    pass


class BudgetExceeded(LlmError):
    """Raised instead of spending past the configured cap (section 7.3)."""


class EmptyCompletion(LlmError):
    """HTTP 200 but no usable content -- see D-030. Retryable."""


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


@dataclass
class LlmClient:
    """Role-routed client with usage logging and a hard budget cap."""

    config: dict[str, Any]
    api_key: str
    usage_log: Path
    calls_made: int = field(default=0, init=False)
    completion_tokens_spent: int = field(default=0, init=False)
    _client: httpx.Client | None = field(default=None, init=False)

    # --- construction ----------------------------------------------------

    @classmethod
    def from_config(
        cls,
        path: Path = DEFAULT_CONFIG,
        *,
        api_key: str | None = None,
        repo_root: Path = REPO_ROOT,
    ) -> LlmClient:
        config = yaml.safe_load(path.read_text(encoding="utf-8"))
        endpoint = config["endpoint"]

        if endpoint.get("api_key"):
            raise LlmError(
                f"{path} contains an inline api_key. The token must come from "
                f"the environment (section 7.1, section 10)."
            )

        env_var = endpoint["api_key_env"]
        key = api_key or os.environ.get(env_var) or _read_dotenv(repo_root, env_var)
        if not key:
            raise LlmError(
                f"no API key: set {env_var} in the environment or in a "
                f"gitignored .env at the repo root"
            )

        usage_log = repo_root / config["budget"]["usage_log"]
        return cls(config=config, api_key=key, usage_log=usage_log)

    def __enter__(self) -> LlmClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def close(self) -> None:
        if self._client is not None:
            self._client.close()
            self._client = None

    # --- routing ---------------------------------------------------------

    @property
    def roles(self) -> list[str]:
        return sorted(self.config["roles"])

    def model_for(self, role: str) -> str:
        roles = self.config["roles"]
        if role not in roles:
            raise LlmError(f"unknown role {role!r}; configured: {sorted(roles)}")
        model = roles[role]["model"]

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

    def _http(self) -> httpx.Client:
        if self._client is None:
            endpoint = self.config["endpoint"]
            self._client = httpx.Client(
                base_url=endpoint["base_url"],
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                },
                timeout=float(endpoint.get("timeout_s", 300)),
            )
        return self._client

    def complete(
        self,
        role: str,
        prompt: str,
        *,
        system: str | None = None,
        max_tokens: int | None = None,
        temperature: float | None = None,
    ) -> Completion:
        """One chat completion for ``role``, with bounded retry."""
        endpoint = self.config["endpoint"]
        handling = self.config.get("response_handling") or {}
        model = self.model_for(role)
        params = self._role_params(role)

        budget_tokens = int(max_tokens or params.get("max_tokens", 4096))
        temp = temperature if temperature is not None else params.get("temperature", 0.0)

        messages: list[dict[str, str]] = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        max_retries = int(endpoint.get("max_retries", 3))
        backoff = float(endpoint.get("retry_backoff_s", 2.0))
        last_error: Exception | None = None

        for attempt in range(1, max_retries + 1):
            self._check_budget()
            body = {
                "model": model,
                "messages": messages,
                "temperature": temp,
                "max_tokens": budget_tokens,
            }

            started = time.time()
            try:
                response = self._http().post(
                    endpoint["chat_completions_path"], json=body
                )
                response.raise_for_status()
                payload = response.json()
            except (httpx.HTTPError, json.JSONDecodeError) as exc:
                last_error = exc
                self._log_usage(
                    role, model, 0, 0, time.time() - started, attempt, str(exc)
                )
                if attempt == max_retries:
                    break
                time.sleep(backoff * attempt)
                continue

            latency = time.time() - started
            self.calls_made += 1

            choice = (payload.get("choices") or [{}])[0]
            message = choice.get("message") or {}
            content = message.get("content")
            reasoning = message.get("reasoning_content")
            finish = choice.get("finish_reason")
            usage = payload.get("usage") or {}

            self.completion_tokens_spent += int(usage.get("completion_tokens", 0) or 0)
            self._log_usage(
                role,
                model,
                int(usage.get("prompt_tokens", 0) or 0),
                int(usage.get("completion_tokens", 0) or 0),
                latency,
                attempt,
                None,
                finish_reason=finish,
                max_tokens=budget_tokens,
                reasoning_chars=len(reasoning or ""),
            )

            # D-030: a reasoning model that ran out of budget returns 200 with
            # content=None. Retry with a bigger budget rather than reporting
            # "no answer", which is what makes this failure mode invisible.
            truncated = finish == "length" and handling.get(
                "treat_length_finish_as_error", True
            )
            if not content or truncated:
                last_error = EmptyCompletion(
                    f"{model} returned finish_reason={finish!r} with "
                    f"{len(reasoning or '')} reasoning chars and "
                    f"{'no' if not content else 'truncated'} content at "
                    f"max_tokens={budget_tokens}"
                )
                if attempt == max_retries:
                    break
                budget_tokens *= 2  # reasoning consumed the budget
                continue

            return Completion(
                role=role,
                model=model,
                content=content,
                reasoning=reasoning,
                finish_reason=finish,
                prompt_tokens=int(usage.get("prompt_tokens", 0) or 0),
                completion_tokens=int(usage.get("completion_tokens", 0) or 0),
                latency_s=latency,
                attempts=attempt,
            )

        raise LlmError(f"role {role!r} failed after {max_retries} attempts") from (
            last_error
        )

    def complete_json(
        self,
        role: str,
        prompt: str,
        model_cls: type[M],
        *,
        system: str | None = None,
        max_tokens: int | None = None,
        retries: int = 1,
    ) -> M:
        """Structured output: JSON-only, fences stripped, validated (CP5).

        Retries once by default on a validation failure, feeding the error back
        so the model can correct it -- cheaper than discarding the attempt.
        """
        # Hand the model the actual schema rather than describing the fields in
        # prose. Without it, models invent plausible neighbouring names --
        # measured: `memcpy_offset` for `length_offset`, and a required field
        # simply omitted -- and the retry cannot recover because it still does
        # not know what the names are supposed to be.
        schema = json.dumps(model_cls.model_json_schema(), separators=(",", ":"))
        instruction = (
            "Respond with a single JSON object and nothing else: no prose, no "
            "explanation, no markdown code fences.\n"
            "The object MUST conform to this JSON Schema, using exactly these "
            f"property names:\n{schema}"
        )
        full_prompt = f"{prompt}\n\n{instruction}"
        last_error: Exception | None = None

        for attempt in range(retries + 1):
            completion = self.complete(
                role, full_prompt, system=system, max_tokens=max_tokens
            )
            candidate = extract_json_object(completion.content)
            try:
                return model_cls.model_validate_json(candidate)
            except (ValidationError, ValueError) as exc:
                last_error = exc
                full_prompt = (
                    f"{prompt}\n\n{instruction}\n\n"
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
