"""GATE 5 -- the LLM client (CLAUDE.md CP5, section 7).

Gate conditions:
  * every configured role resolves to a model returning a valid completion
  * a JSON-constrained call round-trips into a pydantic model
  * usage log populated
  * budget cap triggers when set to a tiny value

The live tests need the endpoint and a key, and cost real allocation, so they are
gated behind ``SNAPFUZZ_LIVE_LLM=1``. Everything checkable offline -- fence
stripping, budget enforcement, routing errors, config hygiene -- always runs.

Run the live half with::

    $env:SNAPFUZZ_LIVE_LLM=1
    .venv\\Scripts\\python.exe -m pytest tests/gates/test_cp5.py -v
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
import yaml
from pydantic import BaseModel

from llm.client import (
    BudgetExceeded,
    LlmClient,
    LlmError,
    extract_json_object,
    strip_code_fences,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
CONFIG = REPO_ROOT / "config" / "llm.yaml"

live_only = pytest.mark.skipif(
    os.environ.get("SNAPFUZZ_LIVE_LLM") != "1",
    reason="set SNAPFUZZ_LIVE_LLM=1 to spend allocation on live endpoint tests",
)


class _Probe(BaseModel):
    """Minimal structured-output target for the round-trip check."""

    magic_hex: str
    min_length: int
    length_offset: int


@pytest.fixture(scope="module")
def client() -> LlmClient:
    """A client built from the real config. NEEDS A KEY -- live tests only.

    `from_config` selects the provider by which key is present, so with none it
    raises "no LLM API key" during SETUP, and a setup error is reported as an ERROR
    rather than a skip. That took two purely offline tests -- role resolution and
    unknown-role rejection, both pure config parsing -- down with it in any
    environment without a key, which is every reviewer's (D-073).
    """
    with LlmClient.from_config(CONFIG) as c:
        yield c


@pytest.fixture(scope="module")
def offline_client(tmp_path_factory) -> LlmClient:
    """The same construction path, with a placeholder key and no network.

    Deliberately still `from_config` against the real `config/llm.yaml`: the thing
    under test is that file's role table and the client's routing over it, so a hand
    built fake would stop testing the part that can actually drift. Only the
    credential is substituted, and nothing here issues a request.
    """
    monkeypatch = pytest.MonkeyPatch()
    providers = yaml.safe_load(CONFIG.read_text(encoding="utf-8"))["providers"]
    for provider in providers.values():
        env = (provider or {}).get("api_key_env")
        if env:
            monkeypatch.delenv(env, raising=False)
    first = next(iter(providers.values()))
    monkeypatch.setenv(first["api_key_env"], "offline-placeholder-not-a-key")
    # `_read_dotenv` would otherwise find the real key and pick whichever provider
    # that file names, making which provider gets tested depend on the machine.
    monkeypatch.setenv("SNAPFUZZ_LLM_PROVIDER", next(iter(providers)))
    with LlmClient.from_config(CONFIG) as c:
        # UNDO IMMEDIATELY, not at teardown. This fixture is module-scoped, so a patch held
        # across the yield stayed in force for every test that ran afterwards -- including
        # the three LIVE ones, which then sent "offline-placeholder-not-a-key" and got
        # 401. GATE 5's live conditions were therefore unrunnable: they were skipped
        # without the flag and failed with it, so the gate could only ever be INCOMPLETE.
        #
        # Safe because `from_config` resolves the credential ONCE and stores it on the
        # client (llm/client.py:328), so `c` keeps the placeholder while the environment
        # goes back to what the machine actually has.
        monkeypatch.undo()
        yield c


# --- config hygiene -------------------------------------------------------


def test_every_provider_declares_a_key_env_and_no_token() -> None:
    """Section 7.1: the URL belongs in config, the token never does.

    Asserted for EVERY provider rather than for one endpoint. A second provider
    added with a pasted key would otherwise sail past the check that exists to
    stop exactly that.
    """
    cfg = yaml.safe_load(CONFIG.read_text(encoding="utf-8"))
    providers = cfg["providers"]
    assert providers, "no providers configured"
    for name, provider in providers.items():
        assert provider.get("api_key") in (None, ""), (
            f"provider {name} has an inline api_key"
        )
        assert provider.get("api_key_env"), f"provider {name} declares no api_key_env"
        assert provider.get("kind"), f"provider {name} declares no kind"
        # A base_url is required for the OpenAI-compatible kind, where it is the
        # only thing identifying the service. The Anthropic SDK supplies its own,
        # so demanding one there would force a wrong value into the config.
        if provider["kind"] == "openai_compatible":
            assert provider.get("base_url", "").startswith("http"), (
                f"provider {name} is openai_compatible with no base_url"
            )


def test_provider_precedence_is_key_presence_then_config_order(tmp_path: Path) -> None:
    """Which provider runs is decided by which key exists, in config order.

    Both directions matter. If precedence stopped following config order, a
    machine with two keys would silently switch provider between runs -- and every
    number in docs/RESULTS.md is attributed to a specific one.
    """
    from llm.client import resolve_provider

    cfg = yaml.safe_load(CONFIG.read_text(encoding="utf-8"))
    names = list(cfg["providers"])
    assert names[0] == "nchc", (
        "nchc must stay first: every measured result came from it, and reordering "
        "would silently re-attribute them"
    )

    # Only the second provider has a key -> the second provider is chosen, even
    # though the first is listed earlier.
    second = names[1]
    (tmp_path / ".env").write_text(
        f"{cfg['providers'][second]['api_key_env']}=sk-test\n", encoding="utf-8"
    )
    assert resolve_provider(cfg, repo_root=tmp_path).name == second

    # Both have keys -> config order decides.
    (tmp_path / ".env").write_text(
        f"{cfg['providers'][names[0]]['api_key_env']}=sk-a\n"
        f"{cfg['providers'][second]['api_key_env']}=sk-b\n",
        encoding="utf-8",
    )
    assert resolve_provider(cfg, repo_root=tmp_path).name == names[0]

    # An explicit request beats both.
    assert (
        resolve_provider(cfg, repo_root=tmp_path, prefer=second).name == second
    )


def test_no_key_anywhere_names_every_variable_it_looked_for(tmp_path: Path) -> None:
    """The error has to say what to set. One variable name would be misleading
    now that any provider's key is enough."""
    from llm.client import LlmError, resolve_provider

    cfg = yaml.safe_load(CONFIG.read_text(encoding="utf-8"))
    with pytest.raises(LlmError, match="no LLM API key") as excinfo:
        resolve_provider(cfg, repo_root=tmp_path)
    message = str(excinfo.value)
    for provider in cfg["providers"].values():
        assert provider["api_key_env"] in message, message


def test_requesting_an_unconfigured_provider_is_an_error(tmp_path: Path) -> None:
    from llm.client import LlmError, resolve_provider

    cfg = yaml.safe_load(CONFIG.read_text(encoding="utf-8"))
    with pytest.raises(LlmError, match="not configured"):
        resolve_provider(cfg, repo_root=tmp_path, prefer="nope")


def test_requesting_a_provider_without_its_key_does_not_fall_through(
    tmp_path: Path,
) -> None:
    """An explicit --provider that has no key must FAIL, not quietly run another.

    Falling through would run a campaign against a provider the operator did not
    ask for and attribute the results to it -- the same class of mistake as D-056.
    """
    from llm.client import LlmError, resolve_provider

    cfg = yaml.safe_load(CONFIG.read_text(encoding="utf-8"))
    (tmp_path / ".env").write_text("SNAPFUZZ_LLM_API_KEY=sk-test\n", encoding="utf-8")
    with pytest.raises(LlmError, match="requested explicitly"):
        resolve_provider(cfg, repo_root=tmp_path, prefer="anthropic")


def test_client_refuses_an_inline_api_key(tmp_path: Path) -> None:
    """A pasted key must fail loudly, not be used."""
    cfg = yaml.safe_load(CONFIG.read_text(encoding="utf-8"))
    cfg["providers"]["nchc"]["api_key"] = "sk-pasted-by-accident"
    bad = tmp_path / "llm.yaml"
    bad.write_text(yaml.safe_dump(cfg), encoding="utf-8")

    with pytest.raises(LlmError, match="inline api_key"):
        LlmClient.from_config(bad, repo_root=tmp_path)


def test_every_role_declares_a_model_and_a_token_budget() -> None:
    """Every role maps a model for every provider that has a key configured.

    The per-provider map is what makes "whichever key exists wins" safe: a role
    with no entry for the active provider must be an error, and the way to keep
    that from happening is to require the entry here.
    """
    cfg = yaml.safe_load(CONFIG.read_text(encoding="utf-8"))
    assert cfg["roles"], "no roles configured"
    providers = set(cfg["providers"])
    for role, spec in cfg["roles"].items():
        models = spec.get("models")
        assert models, f"role {role} has no models map"
        assert set(models) == providers, (
            f"role {role} maps {sorted(models)} but the configured providers are "
            f"{sorted(providers)} -- a missing entry is a run-time failure"
        )
        assert spec.get("max_tokens"), f"role {role} has no max_tokens"


def test_the_default_provider_has_a_model_for_every_role() -> None:
    """`null` is allowed for a provider nobody has verified model ids for, but
    NOT for the one that runs by default -- that would break every campaign."""
    cfg = yaml.safe_load(CONFIG.read_text(encoding="utf-8"))
    default = next(iter(cfg["providers"]))
    for role, spec in cfg["roles"].items():
        assert spec["models"][default], (
            f"role {role} maps the default provider {default!r} to null"
        )


def test_anthropic_roles_name_real_model_aliases() -> None:
    """Claude ids are fixed aliases with NO date suffix.

    Appending a date (`claude-opus-5-20260101`) is the mistake this catches: it
    is a 404 at call time, long after the config was edited.
    """
    import re

    cfg = yaml.safe_load(CONFIG.read_text(encoding="utf-8"))
    known = {name for name in cfg["models"] if name.startswith("claude-")}
    assert known, "no claude models are documented in the models block"
    for role, spec in cfg["roles"].items():
        model = spec["models"].get("anthropic")
        if not model:
            continue
        assert not re.search(r"-\d{8}$", model), (
            f"role {role} uses {model!r}: Claude aliases carry no date suffix"
        )
        assert model in known, (
            f"role {role} uses undocumented Claude model {model!r}; add it to the "
            f"`models` block with its context and output limits"
        )


def test_reasoning_models_get_a_generous_token_budget() -> None:
    """D-030: reasoning is billed against max_tokens.

    Measured: gemma-4-12b needed >600 and gemma-4-26b spent 3984 of 4000 on a
    four-key JSON answer. A budget sized for the answer alone returns
    ``content: null`` on an HTTP 200 -- silently.
    """
    cfg = yaml.safe_load(CONFIG.read_text(encoding="utf-8"))
    reasoning = {
        name
        for name, spec in (cfg.get("models") or {}).items()
        if spec and spec.get("reasoning_model")
    }
    assert reasoning, "no model is marked reasoning_model; D-030 would be forgotten"

    for role, spec in cfg["roles"].items():
        for provider, model in (spec.get("models") or {}).items():
            if model in reasoning:
                assert spec["max_tokens"] >= 4096, (
                    f"role {role} uses reasoning model {model} on {provider} with "
                    f"only {spec['max_tokens']} max_tokens; measured need is >= 4096"
                )


def test_response_handling_declares_the_null_content_case() -> None:
    cfg = yaml.safe_load(CONFIG.read_text(encoding="utf-8"))
    handling = cfg["response_handling"]
    assert handling["content_may_be_null"] is True
    assert handling["treat_length_finish_as_error"] is True
    assert handling["strip_code_fences"] is True


# --- routing --------------------------------------------------------------


def test_roles_resolve_to_models(offline_client: LlmClient) -> None:
    """Resolution is per PROVIDER, so the expected prefix is too.

    This used to assert `startswith("ais3/")` unconditionally, which would have
    failed on a machine whose only key is an Anthropic one -- an assertion that
    encodes one deployment as the only valid one.
    """
    for role in offline_client.roles:
        model = offline_client.model_for(role)
        assert model
        if offline_client.provider_name == "nchc":
            assert model.startswith("ais3/")
        elif offline_client.provider_name == "anthropic":
            assert model.startswith("claude-")


def test_a_role_with_no_model_for_the_active_provider_is_an_error(
    tmp_path: Path,
) -> None:
    """Never a silent default. A model nobody chose is how a campaign gets
    attributed to the wrong one (D-056)."""
    cfg = yaml.safe_load(CONFIG.read_text(encoding="utf-8"))
    cfg["roles"]["triage"]["models"]["nchc"] = None
    path = tmp_path / "llm.yaml"
    path.write_text(yaml.safe_dump(cfg), encoding="utf-8")
    (tmp_path / ".env").write_text("SNAPFUZZ_LLM_API_KEY=sk-test", encoding="utf-8")

    with LlmClient.from_config(path, repo_root=tmp_path) as c:
        with pytest.raises(LlmError, match="null"):
            c.model_for("triage")


def test_unknown_role_is_rejected(offline_client: LlmClient) -> None:
    with pytest.raises(LlmError, match="unknown role"):
        offline_client.model_for("does_not_exist")


def test_excluded_model_cannot_be_routed_to(tmp_path: Path) -> None:
    """llama-guard-3-8b is a safety classifier, not part of this pipeline."""
    cfg = yaml.safe_load(CONFIG.read_text(encoding="utf-8"))
    cfg["roles"]["triage"]["models"]["nchc"] = "ais3/llama-guard-3-8b"
    path = tmp_path / "llm.yaml"
    path.write_text(yaml.safe_dump(cfg), encoding="utf-8")
    (tmp_path / ".env").write_text("SNAPFUZZ_LLM_API_KEY=sk-test", encoding="utf-8")

    with LlmClient.from_config(path, repo_root=tmp_path) as c:
        with pytest.raises(LlmError, match="excluded"):
            c.model_for("triage")


# --- structured output plumbing -------------------------------------------


@pytest.mark.parametrize(
    "raw,expected",
    [
        ('{"a": 1}', '{"a": 1}'),
        ('```json\n{"a": 1}\n```', '{"a": 1}'),
        ('```\n{"a": 1}\n```', '{"a": 1}'),
        ('  ```JSON\n{"a": 1}\n```  ', '{"a": 1}'),
    ],
)
def test_strips_code_fences(raw: str, expected: str) -> None:
    assert strip_code_fences(raw) == expected


def test_extracts_json_from_a_chatty_reply() -> None:
    """Models add prose despite instructions; re-prompting for that is waste."""
    text = 'Sure! Here is the answer:\n\n{"a": 1, "b": 2}\n\nHope that helps.'
    assert json.loads(extract_json_object(text)) == {"a": 1, "b": 2}


def test_extracts_json_arrays_too() -> None:
    assert json.loads(extract_json_object("here: [1, 2, 3]")) == [1, 2, 3]


# --- budget cap -----------------------------------------------------------


def test_budget_cap_triggers_when_tiny(tmp_path: Path) -> None:
    """GATE 5: the cap must refuse, not degrade silently (section 7.3)."""
    cfg = yaml.safe_load(CONFIG.read_text(encoding="utf-8"))
    cfg["budget"]["max_total_calls"] = 0
    path = tmp_path / "llm.yaml"
    path.write_text(yaml.safe_dump(cfg), encoding="utf-8")
    (tmp_path / ".env").write_text("SNAPFUZZ_LLM_API_KEY=sk-test", encoding="utf-8")

    with LlmClient.from_config(path, repo_root=tmp_path) as c:
        with pytest.raises(BudgetExceeded, match="max_total_calls"):
            c.complete("seed_gen", "hello")


def test_token_budget_cap_also_triggers(tmp_path: Path) -> None:
    cfg = yaml.safe_load(CONFIG.read_text(encoding="utf-8"))
    cfg["budget"]["max_total_completion_tokens"] = 0
    path = tmp_path / "llm.yaml"
    path.write_text(yaml.safe_dump(cfg), encoding="utf-8")
    (tmp_path / ".env").write_text("SNAPFUZZ_LLM_API_KEY=sk-test", encoding="utf-8")

    with LlmClient.from_config(path, repo_root=tmp_path) as c:
        with pytest.raises(BudgetExceeded, match="completion tokens"):
            c.complete("seed_gen", "hello")


# --- live endpoint --------------------------------------------------------


@live_only
def test_every_role_returns_a_valid_completion(client: LlmClient) -> None:
    """GATE 5: every configured role resolves to a model that answers."""
    for role in client.roles:
        completion = client.complete(
            role, "Reply with exactly the word: ok", max_tokens=4096
        )
        assert completion.content.strip(), f"role {role} returned empty content"
        assert completion.model == client.model_for(role)
        assert completion.completion_tokens > 0
        print(
            f"  {role:<16} {completion.model:<30} "
            f"{completion.latency_s:5.1f}s  attempts={completion.attempts}"
        )


@live_only
def test_json_call_round_trips_into_a_pydantic_model(client: LlmClient) -> None:
    """GATE 5: a JSON-constrained call validates into a contract."""
    pseudo_c = """
undefined8 FUN_140001150(longlong param_1,uint param_2)
{
  if (param_2 < 8) { return 0; }
  if (*(uint *)(param_1 + 4) != 0x564c54) { return 0; }
  memcpy(dst,(void *)(param_1 + 0xc),(ulonglong)*(uint *)(param_1 + 8));
}
"""
    probe = client.complete_json(
        "entry_select",
        f"Decompiled pseudo-C from a binary with no source:\n{pseudo_c}\n"
        f"Report the magic value it checks as a hex string, the minimum accepted "
        f"length, and the byte offset of the field used as the memcpy size.",
        _Probe,
    )
    assert isinstance(probe, _Probe)
    # The magic is "TLV" little-endian; accept either hex spelling.
    assert probe.magic_hex.lower().replace("0x", "") == "564c54"
    assert probe.min_length == 8
    assert probe.length_offset == 8


@live_only
def test_usage_log_is_populated(client: LlmClient) -> None:
    """GATE 5: usage log populated (section 7.3)."""
    before = (
        len(client.usage_log.read_text(encoding="utf-8").splitlines())
        if client.usage_log.exists()
        else 0
    )
    client.complete("seed_gen", "Reply with exactly: ok", max_tokens=4096)

    lines = client.usage_log.read_text(encoding="utf-8").splitlines()
    assert len(lines) > before

    record = json.loads(lines[-1])
    for key in (
        "role", "model", "prompt_tokens", "completion_tokens", "latency_s",
        "cumulative_calls",
    ):
        assert key in record, f"usage record missing {key}"
    assert record["completion_tokens"] > 0


# --- the Anthropic provider: four things that are not a URL swap -----------
#
# Every test here uses a fake stand-in for the SDK. That is the point: what needs
# defending is the REQUEST this project builds and the RESPONSE reading it does,
# and both are checkable without spending allocation or having a key. The live
# call is covered by the live-only tests above.


class _FakeBlock:
    def __init__(self, type_: str, **fields) -> None:
        self.type = type_
        for key, value in fields.items():
            setattr(self, key, value)


class _FakeUsage:
    def __init__(self, input_tokens: int = 11, output_tokens: int = 22) -> None:
        self.input_tokens = input_tokens
        self.output_tokens = output_tokens


class _FakeMessage:
    def __init__(
        self,
        *,
        content=None,
        stop_reason="end_turn",
        model="claude-opus-5",
        stop_details=None,
    ) -> None:
        self.content = content if content is not None else [_FakeBlock("text", text="hi")]
        self.stop_reason = stop_reason
        self.model = model
        self.stop_details = stop_details
        self.usage = _FakeUsage()


class _FakeMessages:
    """Records the request instead of sending it."""

    def __init__(self, reply=None) -> None:
        self.calls: list[dict] = []
        self._reply = reply

    def create(self, **body):
        self.calls.append(body)
        reply = self._reply
        if callable(reply):
            return reply(**body)
        return reply or _FakeMessage()


class _FakeSdk:
    def __init__(self, reply=None) -> None:
        self.messages = _FakeMessages(reply)
        # `beta.messages.create` is the path taken when fallbacks are requested.
        self.beta = type("_Beta", (), {"messages": self.messages})()


def _anthropic_provider(reply=None, **config):
    from llm.providers import AnthropicProvider

    settings = {"kind": "anthropic", "api_key_env": "ANTHROPIC_API_KEY"}
    settings.update(config)
    provider = AnthropicProvider(config=settings, api_key="sk-test")
    provider._client = _FakeSdk(reply)
    return provider


def test_anthropic_never_sends_temperature() -> None:
    """`temperature`/`top_p`/`top_k` are an HTTP 400 on the current Claude models.

    Every role in this project configures a temperature, so forwarding it would
    400 on the very first call. This is the single most likely way a port breaks.
    """
    provider = _anthropic_provider()
    provider.complete(
        model="claude-opus-5",
        prompt="p",
        system=None,
        max_tokens=100,
        params={"temperature": 0.9, "max_tokens": 100},
    )
    body = provider._client.messages.calls[0]
    for banned in ("temperature", "top_p", "top_k"):
        assert banned not in body, f"{banned} would be rejected with a 400"


def test_anthropic_translates_temperature_into_effort() -> None:
    """The configured temperature is intent, and the intent survives the
    translation: 0.0 means "one right answer", 0.9 means "be diverse"."""
    from llm.providers import effort_for_temperature

    # 0.0 maps to `high`, NOT `xhigh`. Thinking is on by default and billed against
    # max_tokens, which caps thinking and text together; the roles at 0.0 carry
    # budgets sized for a JSON answer, so xhigh can spend the whole budget thinking
    # and force the doubling retry -- two calls to get one.
    assert effort_for_temperature(0.0) == "high"
    assert effort_for_temperature(0.2) == "high"
    assert effort_for_temperature(0.9) == "medium"
    # Absent temperature must still produce a valid level, not None.
    assert effort_for_temperature(None) == "high"
    # The diversity role must NOT get the deliberate setting: that would spend the
    # budget on depth for a task where depth is not the point.
    assert effort_for_temperature(0.9) != effort_for_temperature(0.0)

    provider = _anthropic_provider()
    provider.complete(
        model="claude-opus-5", prompt="p", system=None, max_tokens=100,
        params={"temperature": 0.0},
    )
    assert provider._client.messages.calls[0]["output_config"]["effort"] == "high"


def test_anthropic_asks_for_summarized_thinking() -> None:
    """Default display is "omitted", which returns thinking blocks with empty text.

    The usage log records reasoning length so a budget consumed by thinking is
    visible rather than mysterious -- the diagnostic D-030 needed. With the default
    that number is always zero: a metric that cannot move.
    """
    provider = _anthropic_provider()
    provider.complete(
        model="claude-opus-5", prompt="p", system=None, max_tokens=100, params={}
    )
    thinking = provider._client.messages.calls[0]["thinking"]
    assert thinking["display"] == "summarized"


def test_anthropic_schema_translation_satisfies_the_api_requirements() -> None:
    """Anthropic structured outputs require `additionalProperties: false` on every
    object and reject the numeric/string constraints pydantic emits.

    Handing a raw pydantic schema across would be an HTTP 400 on every structured
    call -- not a degraded answer, a hard failure of the whole feature.
    """
    from llm.providers import anthropic_json_schema

    raw = {
        "type": "object",
        "properties": {
            "n": {"type": "integer", "minimum": 0, "maximum": 10},
            "s": {"type": "string", "maxLength": 8, "pattern": "^a"},
            "nested": {
                "type": "object",
                "properties": {"x": {"type": "integer", "multipleOf": 2}},
            },
            "items": {"type": "array", "items": {"type": "object", "properties": {}}},
        },
        "required": ["n"],
    }
    out = anthropic_json_schema(raw)

    assert out["additionalProperties"] is False
    assert out["properties"]["nested"]["additionalProperties"] is False
    assert out["properties"]["items"]["items"]["additionalProperties"] is False
    for banned in ("minimum", "maximum"):
        assert banned not in out["properties"]["n"]
    for banned in ("maxLength", "pattern"):
        assert banned not in out["properties"]["s"]
    assert "multipleOf" not in out["properties"]["nested"]["properties"]["x"]
    # The caller's schema is untouched -- it is still used for real validation.
    assert raw["properties"]["n"]["minimum"] == 0


def test_native_json_is_off_until_someone_verifies_it() -> None:
    """Opt-in, because getting the schema wrong is a 400 on every structured call
    and the prompted path is already proven. This pins the default rather than the
    capability: flipping it on is a config edit, and it should be a deliberate one.
    """
    import yaml as _yaml

    cfg = _yaml.safe_load(CONFIG.read_text(encoding="utf-8"))
    assert cfg["providers"]["anthropic"].get("native_json") is False

    assert _anthropic_provider().supports_native_json is False
    assert _anthropic_provider(native_json=True).supports_native_json is True


def test_anthropic_puts_system_at_the_top_level_not_in_messages() -> None:
    """`{"role": "system"}` inside messages is a DIFFERENT, model-gated feature.

    Sending the initial system prompt that way is wrong on a model that rejects
    it and subtly wrong on one that does not.
    """
    provider = _anthropic_provider()
    provider.complete(
        model="claude-opus-5", prompt="p", system="be terse",
        max_tokens=100, params={},
    )
    body = provider._client.messages.calls[0]
    assert body["system"] == "be terse"
    assert [m["role"] for m in body["messages"]] == ["user"]


def test_anthropic_always_sends_max_tokens() -> None:
    """Required by the API -- omitting it is a 400, not a default."""
    provider = _anthropic_provider()
    provider.complete(
        model="claude-opus-5", prompt="p", system=None, max_tokens=4096, params={}
    )
    assert provider._client.messages.calls[0]["max_tokens"] == 4096


def test_anthropic_reads_text_blocks_and_ignores_thinking() -> None:
    """The response is a LIST OF BLOCKS. `content[0].text` is wrong when the
    first block is a thinking block, which it is by default on Opus 5."""
    reply = _FakeMessage(
        content=[
            _FakeBlock("thinking", thinking="deliberating"),
            _FakeBlock("text", text="the "),
            _FakeBlock("text", text="answer"),
        ]
    )
    provider = _anthropic_provider(reply)
    raw = provider.complete(
        model="claude-opus-5", prompt="p", system=None, max_tokens=100, params={}
    )
    assert raw.content == "the answer"
    assert raw.reasoning == "deliberating"


def test_anthropic_refusal_raises_before_content_is_touched() -> None:
    """A policy decline is a successful 200 with an EMPTY content list.

    Indexing content[0] here is the bug the ordering exists to prevent, and it
    matters unusually much in this project: triage sends fault addresses and
    memory-corruption analysis, which is what the cyber classifiers screen.
    """
    from llm.providers import ProviderRefusal

    details = type("_D", (), {"category": "cyber"})()
    reply = _FakeMessage(content=[], stop_reason="refusal", stop_details=details)
    provider = _anthropic_provider(reply)
    with pytest.raises(ProviderRefusal) as excinfo:
        provider.complete(
            model="claude-opus-5", prompt="p", system=None, max_tokens=100, params={}
        )
    assert excinfo.value.category == "cyber"


def test_client_surfaces_a_refusal_as_refused_and_does_not_retry(
    tmp_path: Path,
) -> None:
    """Retrying a decline burns allocation and never succeeds. And "no verdict"
    must stay distinguishable from "judged benign" -- collapsing them would
    silently drop findings."""
    from llm.client import Refused

    cfg = yaml.safe_load(CONFIG.read_text(encoding="utf-8"))
    path = tmp_path / "llm.yaml"
    path.write_text(yaml.safe_dump(cfg), encoding="utf-8")
    (tmp_path / ".env").write_text("ANTHROPIC_API_KEY=sk-test", encoding="utf-8")

    details = type("_D", (), {"category": "cyber"})()
    reply = _FakeMessage(content=[], stop_reason="refusal", stop_details=details)

    with LlmClient.from_config(path, repo_root=tmp_path, provider="anthropic") as c:
        provider = c._backend()
        provider._client = _FakeSdk(reply)
        with pytest.raises(Refused) as excinfo:
            c.complete("triage", "analyse this crash")
        assert excinfo.value.category == "cyber"
        # Exactly one attempt: no retry loop on a policy decline.
        assert len(provider._client.messages.calls) == 1


def test_anthropic_max_tokens_stop_is_treated_as_truncation(tmp_path: Path) -> None:
    """Thinking is on by default and billed against max_tokens -- the same
    failure D-030 documents for the NCHC reasoning models. The budget must be
    doubled and retried, not reported as an answer."""
    cfg = yaml.safe_load(CONFIG.read_text(encoding="utf-8"))
    path = tmp_path / "llm.yaml"
    path.write_text(yaml.safe_dump(cfg), encoding="utf-8")
    (tmp_path / ".env").write_text("ANTHROPIC_API_KEY=sk-test", encoding="utf-8")

    attempts: list[int] = []

    def reply(**body):
        attempts.append(body["max_tokens"])
        if len(attempts) == 1:
            return _FakeMessage(
                content=[_FakeBlock("text", text="half an ans")],
                stop_reason="max_tokens",
            )
        return _FakeMessage(content=[_FakeBlock("text", text="whole answer")])

    with LlmClient.from_config(path, repo_root=tmp_path, provider="anthropic") as c:
        provider = c._backend()
        provider._client = _FakeSdk(reply)
        completion = c.complete("triage", "hello")

    assert completion.content == "whole answer"
    assert attempts[1] == attempts[0] * 2, f"budget was not doubled: {attempts}"


def test_anthropic_requests_fallbacks_by_default() -> None:
    """On by default for THIS project: a declined triage call would otherwise
    lose the verdict entirely."""
    provider = _anthropic_provider()
    provider.complete(
        model="claude-opus-5", prompt="p", system=None, max_tokens=100, params={}
    )
    body = provider._client.messages.calls[0]
    assert body.get("fallbacks") == "default"
    assert any("server-side-fallback" in b for b in body.get("betas", []))


def test_anthropic_fallbacks_can_be_switched_off() -> None:
    provider = _anthropic_provider(request_fallbacks=False)
    provider.complete(
        model="claude-opus-5", prompt="p", system=None, max_tokens=100, params={}
    )
    body = provider._client.messages.calls[0]
    assert "fallbacks" not in body and "betas" not in body


def test_anthropic_records_the_model_that_actually_answered() -> None:
    """A fallback means a different model served the request. A usage log naming
    only the requested model would be wrong about the spend."""
    reply = _FakeMessage(model="claude-opus-4-8")
    provider = _anthropic_provider(reply)
    raw = provider.complete(
        model="claude-opus-5", prompt="p", system=None, max_tokens=100, params={}
    )
    assert raw.served_model == "claude-opus-4-8"


def test_anthropic_json_goes_through_the_schema_when_enabled(tmp_path: Path) -> None:
    """With native_json on: schema on the request, no JSON-only instruction, no
    fences to strip, and the schema translated to what the API accepts."""
    from pydantic import BaseModel

    class Tiny(BaseModel):
        a: int

    cfg = yaml.safe_load(CONFIG.read_text(encoding="utf-8"))
    path = tmp_path / "llm.yaml"
    path.write_text(yaml.safe_dump(cfg), encoding="utf-8")
    (tmp_path / ".env").write_text("ANTHROPIC_API_KEY=sk-test", encoding="utf-8")

    reply = _FakeMessage(content=[_FakeBlock("text", text='{"a": 1}')])
    # Read the recorded call INSIDE the context: leaving it drops the SDK handle,
    # which is correct behaviour and made the first version of this test fail on
    # a NoneType rather than on the thing it was checking.
    with LlmClient.from_config(path, repo_root=tmp_path, provider="anthropic") as c:
        provider = c._backend()
        provider.supports_native_json = True  # the config default is off
        provider._client = _FakeSdk(reply)
        assert c.complete_json("triage", "extract it", Tiny).a == 1
        body = provider._client.messages.calls[0]

    fmt = body["output_config"]["format"]
    assert fmt["type"] == "json_schema"
    assert fmt["schema"]["properties"]["a"]
    # Translated, not passed through: the API rejects a schema without this.
    assert fmt["schema"]["additionalProperties"] is False
    # The prompt stays clean -- the schema is not also described in prose.
    prompt = body["messages"][0]["content"]
    assert "JSON Schema" not in prompt and "code fences" not in prompt


def test_anthropic_falls_back_to_the_prompted_path_by_default(tmp_path: Path) -> None:
    """With native_json off (the default) the Anthropic path must behave like the
    others: schema in the prompt, reply de-fenced. Otherwise a fresh Anthropic key
    gets no structured output at all."""
    from pydantic import BaseModel

    class Tiny(BaseModel):
        a: int

    cfg = yaml.safe_load(CONFIG.read_text(encoding="utf-8"))
    path = tmp_path / "llm.yaml"
    path.write_text(yaml.safe_dump(cfg), encoding="utf-8")
    (tmp_path / ".env").write_text("ANTHROPIC_API_KEY=sk-test", encoding="utf-8")

    reply = _FakeMessage(content=[_FakeBlock("text", text='```json\n{"a": 1}\n```')])
    with LlmClient.from_config(path, repo_root=tmp_path, provider="anthropic") as c:
        provider = c._backend()
        provider._client = _FakeSdk(reply)
        assert c.complete_json("triage", "extract it", Tiny).a == 1
        body = provider._client.messages.calls[0]

    assert "format" not in body["output_config"]
    assert "JSON Schema" in body["messages"][0]["content"]


def test_openai_compatible_still_asks_for_json_in_the_prompt(tmp_path: Path) -> None:
    """The counterpart: a provider with no native enforcement MUST still get the
    schema in the prompt, or it invents neighbouring field names (D-046)."""
    from pydantic import BaseModel

    class Tiny(BaseModel):
        a: int

    cfg = yaml.safe_load(CONFIG.read_text(encoding="utf-8"))
    path = tmp_path / "llm.yaml"
    path.write_text(yaml.safe_dump(cfg), encoding="utf-8")
    (tmp_path / ".env").write_text("SNAPFUZZ_LLM_API_KEY=sk-test", encoding="utf-8")

    seen: dict = {}

    def fake_complete(*, model, prompt, system, max_tokens, params):
        from llm.providers import RawCompletion

        seen["prompt"] = prompt
        return RawCompletion(
            content='{"a": 1}', reasoning=None, finish_reason="stop",
            prompt_tokens=1, completion_tokens=1, truncated=False,
        )

    with LlmClient.from_config(path, repo_root=tmp_path, provider="nchc") as c:
        provider = c._backend()
        provider.complete = fake_complete  # type: ignore[method-assign]
        assert c.complete_json("triage", "extract it", Tiny).a == 1

    assert "JSON Schema" in seen["prompt"]


def test_usage_log_records_the_provider(tmp_path: Path) -> None:
    """Two providers writing one log is only readable if each line says which."""
    cfg = yaml.safe_load(CONFIG.read_text(encoding="utf-8"))
    path = tmp_path / "llm.yaml"
    path.write_text(yaml.safe_dump(cfg), encoding="utf-8")
    (tmp_path / ".env").write_text("ANTHROPIC_API_KEY=sk-test", encoding="utf-8")

    with LlmClient.from_config(path, repo_root=tmp_path, provider="anthropic") as c:
        c._backend()._client = _FakeSdk()
        c.complete("triage", "hello")

    lines = (tmp_path / cfg["budget"]["usage_log"]).read_text(
        encoding="utf-8"
    ).strip().splitlines()
    record = json.loads(lines[-1])
    assert record["provider"] == "anthropic"
    assert record["model"] == "claude-opus-5"
