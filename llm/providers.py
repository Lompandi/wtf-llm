"""Provider backends for the role-routed client: OpenAI-compatible and Anthropic.

The client takes a ROLE, never a model name (CLAUDE.md section 7.2). This module
is the layer below that: given a resolved model and parameters, it performs one
call and normalises the result. Adding a provider must not change any caller.

**Which provider runs is decided by which API KEY is present**, in the order
listed in `config/llm.yaml`. That is deliberate -- it means a machine with only
an Anthropic key and a machine with only the NCHC key both work from the same
checkout, with no config edit and no flag.

Two providers, and they are NOT the same wire format:

* `openai_compatible` -- `POST /chat/completions`, `Authorization: Bearer`,
  `system` as a message, `choices[0].message.content`. Covers the NCHC/AIS3
  endpoint and OpenAI itself. Uses httpx, as this project already did.
* `anthropic` -- `POST /v1/messages` via the official `anthropic` SDK. Different
  in four ways that each break a naive port, all handled below.

### The four things that are not a URL swap

**1. `temperature` is REJECTED on the current models.** Claude Opus 5, Fable 5,
Opus 4.8 and 4.7 return HTTP 400 if `temperature`, `top_p`, or `top_k` is sent.
Every role in this project sets a temperature, so a direct port 400s on the
first call. The mapping used here is `temperature -> effort`: a role that asked
for 0.0 wanted one right answer, which is `effort: high`; a role that asked for
0.9 wanted diversity, which Claude gets from independent samples rather than a
sampling knob (the seed-gen sidecar already issues N independent calls and
unions them -- that mechanism survives, the temperature does not).

**2. `system` is a top-level field, not a message.** Passing it as
`{"role": "system", ...}` inside `messages` is a different feature with model
gating; the initial system prompt belongs in the `system` parameter.

**3. The response is a LIST OF BLOCKS, and may be a refusal.** `content[0].text`
is wrong twice over: blocks can be `thinking` rather than `text`, and on a
policy decline `stop_reason == "refusal"` with an EMPTY content list. That last
one matters unusually much here -- this project sends the model crash dumps,
fault addresses and memory-corruption analysis, which is exactly the material
Claude's cyber classifiers screen. So `stop_reason` is checked before `content`
is touched, and server-side fallbacks are requested by default so a decline is
recovered rather than surfaced as "the model had no verdict".

**4. Thinking is ON by default and billed against `max_tokens`.** Which is the
same failure this project already documented for the NCHC reasoning models
(D-030): budget exhausted during reasoning, no usable answer. The existing
"retry with a doubled budget" logic in the client is therefore correct for
Claude too -- it just triggers on `stop_reason == "max_tokens"` instead of
`finish_reason == "length"`.

Structured output differs too, and here Claude is strictly better: instead of
asking for JSON in prose and stripping code fences afterwards, the schema is
enforced by the API (`output_config.format`). `supports_native_json` advertises
that so the client can skip the fence-stripping path.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Any, Protocol

__all__ = [
    "ProviderError",
    "ProviderRefusal",
    "RawCompletion",
    "Provider",
    "OpenAICompatibleProvider",
    "AnthropicProvider",
    "build_provider",
]


class ProviderError(RuntimeError):
    pass


class ProviderRefusal(ProviderError):
    """The model declined on policy grounds. NOT a transport error.

    Kept distinct because the response is a successful HTTP 200 with an empty
    content list -- code that retries transport failures would retry this
    forever, and code that reads content would report an empty answer.
    """

    def __init__(self, message: str, *, category: str | None = None) -> None:
        super().__init__(message)
        self.category = category


@dataclass(frozen=True)
class RawCompletion:
    """One provider response, normalised.

    ``truncated`` is the provider's own signal that the budget ran out mid-answer
    -- ``finish_reason == "length"`` on OpenAI-compatible, ``stop_reason ==
    "max_tokens"`` on Anthropic. The client retries those with a larger budget
    rather than treating a half-answer as an answer.
    """

    content: str | None
    reasoning: str | None
    finish_reason: str | None
    prompt_tokens: int
    completion_tokens: int
    truncated: bool
    # What actually served the request. On Anthropic this can differ from the
    # requested model when a refusal was recovered by a fallback, and a usage log
    # that recorded the requested model would be quietly wrong about the spend.
    served_model: str | None = None


class Provider(Protocol):
    kind: str
    supports_native_json: bool

    def complete(
        self,
        *,
        model: str,
        prompt: str,
        system: str | None,
        max_tokens: int,
        params: dict[str, Any],
    ) -> RawCompletion: ...

    def complete_json(
        self,
        *,
        model: str,
        prompt: str,
        system: str | None,
        max_tokens: int,
        params: dict[str, Any],
        schema: dict[str, Any],
    ) -> RawCompletion: ...

    def close(self) -> None: ...


# --- OpenAI-compatible ----------------------------------------------------


@dataclass
class OpenAICompatibleProvider:
    """`/chat/completions` with a bearer token. NCHC/AIS3, OpenAI, vLLM, ...

    Unchanged in behaviour from the single-provider client this replaced, so the
    measured NCHC quirks in D-029/D-030 still hold on this path.
    """

    config: dict[str, Any]
    api_key: str
    kind: str = "openai_compatible"
    # Left False even for real OpenAI: `response_format` support varies across
    # everything that claims OpenAI compatibility, and claiming it here would
    # skip the fence-stripping fallback that makes the NCHC endpoint usable.
    supports_native_json: bool = False

    def __post_init__(self) -> None:
        self._client = None

    def _http(self):
        import httpx

        if self._client is None:
            self._client = httpx.Client(
                base_url=self.config["base_url"],
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                },
                timeout=float(self.config.get("timeout_s", 300)),
            )
        return self._client

    def complete(
        self,
        *,
        model: str,
        prompt: str,
        system: str | None,
        max_tokens: int,
        params: dict[str, Any],
    ) -> RawCompletion:
        import httpx

        messages: list[dict[str, str]] = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        body: dict[str, Any] = {
            "model": model,
            "messages": messages,
            "max_tokens": max_tokens,
        }
        if params.get("temperature") is not None:
            body["temperature"] = float(params["temperature"])

        try:
            response = self._http().post(
                self.config.get("chat_completions_path", "/chat/completions"), json=body
            )
            response.raise_for_status()
            payload = response.json()
        except (httpx.HTTPError, json.JSONDecodeError) as exc:
            raise ProviderError(str(exc)) from exc

        choice = (payload.get("choices") or [{}])[0]
        message = choice.get("message") or {}
        usage = payload.get("usage") or {}
        finish = choice.get("finish_reason")

        return RawCompletion(
            content=message.get("content"),
            reasoning=message.get("reasoning_content"),
            finish_reason=finish,
            prompt_tokens=int(usage.get("prompt_tokens", 0) or 0),
            completion_tokens=int(usage.get("completion_tokens", 0) or 0),
            truncated=finish == "length",
            served_model=payload.get("model") or model,
        )

    def complete_json(self, *, schema: dict[str, Any], **kwargs: Any) -> RawCompletion:
        """No native schema enforcement -- the client asks for JSON in the prompt.

        `schema` is accepted and ignored so the two providers present the same
        surface; the client checks `supports_native_json` to decide which path to
        prepare the prompt for.
        """
        return self.complete(**kwargs)

    def close(self) -> None:
        if self._client is not None:
            self._client.close()
            self._client = None


# --- Anthropic ------------------------------------------------------------

# temperature -> effort. Claude has no sampling knob on the current models, so a
# configured temperature is read as a statement of INTENT and translated:
# "one right answer" becomes deeper deliberation, "be diverse" becomes less.
# Diversity itself comes from independent samples, which is how the seed-gen
# sidecar already works.
# `high` for 0.0 rather than `xhigh`, deliberately. Thinking is on by default and
# is billed against `max_tokens`, which caps thinking and text TOGETHER -- and the
# roles at temperature 0.0 carry 8192-16384 token budgets sized for a JSON answer,
# not for xhigh-level deliberation plus that answer. At xhigh the budget can go
# entirely on thinking, which surfaces as `stop_reason: "max_tokens"` with the
# answer truncated: the client doubles and retries, so it recovers, but it pays for
# two calls to get one. Raise both together if you want more depth.
_EFFORT_BY_TEMPERATURE = (
    (0.05, "high"),  # 0.0 -- exactly one correct answer (input_struct, triage)
    (0.35, "high"),  # 0.2 -- code comprehension with a right answer
    (1.01, "medium"),  # 0.7-0.9 -- diversity wanted; depth is not the point
)

# Requested by default on the current Opus models. This project's triage role
# sends fault addresses, register dumps and memory-corruption analysis, so a
# cyber-category decline is a live possibility rather than a hypothetical; the
# fallback recovers it server-side instead of losing the verdict.
_FALLBACK_BETA = "server-side-fallback-2026-07-01"


def effort_for_temperature(temperature: float | None) -> str:
    if temperature is None:
        return "high"
    for ceiling, effort in _EFFORT_BY_TEMPERATURE:
        if float(temperature) < ceiling:
            return effort
    return "medium"


def anthropic_json_schema(schema: dict[str, Any]) -> dict[str, Any]:
    """A pydantic schema Anthropic's structured outputs will accept.

    Two required edits pydantic does not make. Every object needs
    ``additionalProperties: false``, and the numeric/string constraints pydantic
    emits (``minimum``, ``maxLength``, ``multipleOf``, ...) are not supported and
    are rejected. Dropping them here is safe because the reply is validated
    against the real model afterwards either way -- the schema is a generation
    constraint, not the validation.

    Returns a copy; the caller's schema is not mutated.
    """
    unsupported = {
        "minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum", "multipleOf",
        "minLength", "maxLength", "pattern", "minItems", "maxItems", "uniqueItems",
        "minProperties", "maxProperties",
    }

    def walk(node: Any) -> Any:
        if isinstance(node, list):
            return [walk(item) for item in node]
        if not isinstance(node, dict):
            return node
        out = {key: walk(value) for key, value in node.items() if key not in unsupported}
        if out.get("type") == "object" or "properties" in out:
            out.setdefault("additionalProperties", False)
        return out

    return walk(schema)


@dataclass
class AnthropicProvider:
    """`/v1/messages` through the official `anthropic` SDK.

    The SDK rather than raw httpx deliberately: it owns the auth headers, the
    `anthropic-version` header, typed errors, and retry/backoff, none of which
    this project should re-derive. It is imported lazily so a checkout that only
    uses the OpenAI-compatible endpoint does not need the dependency.
    """

    config: dict[str, Any]
    api_key: str
    kind: str = "anthropic"
    # OPT-IN, default off. `output_config.format` is the better mechanism -- the
    # API enforces the schema instead of the prompt asking for it -- but it has
    # requirements pydantic does not satisfy (`additionalProperties: false` on
    # every object, no numeric/string constraints), and getting them wrong is an
    # HTTP 400 on every structured call rather than a degraded answer.
    # `anthropic_json_schema` above does the translation; this stays off until
    # someone has confirmed it against the live API, because the prompted path is
    # already proven and shipping an unverified 400 is worse than shipping a
    # working prompt. Turn on with `native_json: true` in config/llm.yaml.
    supports_native_json: bool = False

    def __post_init__(self) -> None:
        self._client = None
        if self.config.get("native_json"):
            self.supports_native_json = True

    def _sdk(self):
        if self._client is None:
            try:
                import anthropic
            except ImportError as exc:
                raise ProviderError(
                    "the anthropic provider needs the official SDK: "
                    "pip install anthropic"
                ) from exc
            kwargs: dict[str, Any] = {
                "api_key": self.api_key,
                "timeout": float(self.config.get("timeout_s", 600)),
                "max_retries": int(self.config.get("max_retries", 2)),
            }
            if self.config.get("base_url"):
                kwargs["base_url"] = self.config["base_url"]
            self._client = anthropic.Anthropic(**kwargs)
        return self._client

    # --- request assembly ------------------------------------------------

    def _request(
        self,
        *,
        model: str,
        prompt: str,
        system: str | None,
        max_tokens: int,
        params: dict[str, Any],
    ) -> dict[str, Any]:
        body: dict[str, Any] = {
            "model": model,
            "max_tokens": max_tokens,
            # Top-level, NOT a message. A `{"role": "system"}` entry in messages
            # is the separate mid-conversation feature and is model-gated.
            "messages": [{"role": "user", "content": prompt}],
            "output_config": {"effort": effort_for_temperature(params.get("temperature"))},
            # display defaults to "omitted", which returns thinking blocks whose
            # text is empty. The usage log records reasoning length to make a
            # budget consumed by thinking visible rather than mysterious (the same
            # diagnostic D-030 needed), and with the default that number is always
            # zero -- a metric that cannot move. Billing is identical either way.
            "thinking": {"type": "adaptive", "display": "summarized"},
        }
        if system:
            body["system"] = system
        # temperature/top_p/top_k are NOT forwarded. They are a 400 on the
        # current models; the intent is carried by `effort` above.
        return body

    def _fallback_kwargs(self) -> dict[str, Any]:
        if not self.config.get("request_fallbacks", True):
            return {}
        return {"betas": [_FALLBACK_BETA], "fallbacks": "default"}

    # --- response reading ------------------------------------------------

    @staticmethod
    def _read(message: Any, requested_model: str) -> RawCompletion:
        stop = getattr(message, "stop_reason", None)

        # Checked BEFORE content. A refusal is a successful 200 whose content
        # list is empty; indexing content[0] here is the bug this ordering
        # exists to prevent.
        if stop == "refusal":
            details = getattr(message, "stop_details", None)
            category = getattr(details, "category", None) if details else None
            raise ProviderRefusal(
                f"{requested_model} declined the request"
                + (f" (category={category})" if category else "")
                + ". This project sends crash and memory-corruption material, "
                "which the cyber classifiers screen -- see providers.py.",
                category=category,
            )

        text_parts: list[str] = []
        thinking_parts: list[str] = []
        for block in getattr(message, "content", None) or []:
            block_type = getattr(block, "type", None)
            if block_type == "text":
                text_parts.append(getattr(block, "text", "") or "")
            elif block_type == "thinking":
                # Empty unless display="summarized"; kept for the usage log so a
                # budget consumed by thinking is visible rather than mysterious.
                thinking_parts.append(getattr(block, "thinking", "") or "")

        usage = getattr(message, "usage", None)
        content = "".join(text_parts) or None
        return RawCompletion(
            content=content,
            reasoning="".join(thinking_parts) or None,
            finish_reason=stop,
            prompt_tokens=int(getattr(usage, "input_tokens", 0) or 0) if usage else 0,
            completion_tokens=int(getattr(usage, "output_tokens", 0) or 0) if usage else 0,
            # Same shape as the NCHC reasoning failure (D-030): the budget went
            # on thinking and the answer is absent or cut off.
            truncated=stop == "max_tokens",
            served_model=getattr(message, "model", None) or requested_model,
        )

    def complete(
        self,
        *,
        model: str,
        prompt: str,
        system: str | None,
        max_tokens: int,
        params: dict[str, Any],
    ) -> RawCompletion:
        body = self._request(
            model=model,
            prompt=prompt,
            system=system,
            max_tokens=max_tokens,
            params=params,
        )
        client = self._sdk()
        fallbacks = self._fallback_kwargs()
        try:
            if fallbacks:
                message = client.beta.messages.create(**body, **fallbacks)
            else:
                message = client.messages.create(**body)
        except ProviderError:
            raise
        except Exception as exc:  # SDK errors are typed but many; one boundary
            raise ProviderError(f"{type(exc).__name__}: {exc}") from exc
        return self._read(message, model)

    def complete_json(
        self,
        *,
        model: str,
        prompt: str,
        system: str | None,
        max_tokens: int,
        params: dict[str, Any],
        schema: dict[str, Any],
    ) -> RawCompletion:
        """Schema enforced by the API rather than requested in prose.

        This is why `supports_native_json` is True: the client can skip the
        "reply with JSON only, no fences" instruction and the fence-stripping
        that follows it. Note `output_config.format` is incompatible with
        citations, and a `max_tokens` stop still yields truncated JSON -- so the
        client's validate-and-retry loop stays useful either way.
        """
        body = self._request(
            model=model,
            prompt=prompt,
            system=system,
            max_tokens=max_tokens,
            params=params,
        )
        body["output_config"] = {
            **body["output_config"],
            "format": {
                "type": "json_schema",
                "schema": anthropic_json_schema(schema),
            },
        }
        client = self._sdk()
        fallbacks = self._fallback_kwargs()
        try:
            if fallbacks:
                message = client.beta.messages.create(**body, **fallbacks)
            else:
                message = client.messages.create(**body)
        except ProviderError:
            raise
        except Exception as exc:
            raise ProviderError(f"{type(exc).__name__}: {exc}") from exc
        return self._read(message, model)

    def close(self) -> None:
        # Actually closed, not just dropped. `LlmClient.__exit__` means "released
        # the connections" on the OpenAI-compatible provider, and it has to mean
        # the same here rather than leaving the SDK's pool to the garbage
        # collector.
        client, self._client = self._client, None
        if client is not None:
            closer = getattr(client, "close", None)
            if callable(closer):
                try:
                    closer()
                except Exception:
                    # Teardown must not raise: this runs from __exit__, where an
                    # exception would mask whatever the caller was actually doing.
                    pass


# --- construction ---------------------------------------------------------

_KINDS = {
    "openai_compatible": OpenAICompatibleProvider,
    "anthropic": AnthropicProvider,
}


def build_provider(name: str, config: dict[str, Any], api_key: str) -> Provider:
    kind = config.get("kind")
    if kind not in _KINDS:
        raise ProviderError(
            f"provider {name!r} has kind {kind!r}; known kinds are "
            f"{sorted(_KINDS)}"
        )
    return _KINDS[kind](config=config, api_key=api_key)
