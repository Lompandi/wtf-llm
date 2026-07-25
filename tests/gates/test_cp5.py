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
    with LlmClient.from_config(CONFIG) as c:
        yield c


# --- config hygiene -------------------------------------------------------


def test_config_has_a_base_url_and_no_token() -> None:
    """Section 7.1: the URL belongs in config, the token never does."""
    cfg = yaml.safe_load(CONFIG.read_text(encoding="utf-8"))
    endpoint = cfg["endpoint"]
    assert endpoint["base_url"], "base_url is still null -- CP5 requires filling it"
    assert endpoint["base_url"].startswith("http")
    assert endpoint.get("api_key") in (None, "")
    assert endpoint["api_key_env"]


def test_client_refuses_an_inline_api_key(tmp_path: Path) -> None:
    """A pasted key must fail loudly, not be used."""
    cfg = yaml.safe_load(CONFIG.read_text(encoding="utf-8"))
    cfg["endpoint"]["api_key"] = "sk-pasted-by-accident"
    bad = tmp_path / "llm.yaml"
    bad.write_text(yaml.safe_dump(cfg), encoding="utf-8")

    with pytest.raises(LlmError, match="inline api_key"):
        LlmClient.from_config(bad, repo_root=tmp_path)


def test_every_role_declares_a_model_and_a_token_budget() -> None:
    cfg = yaml.safe_load(CONFIG.read_text(encoding="utf-8"))
    assert cfg["roles"], "no roles configured"
    for role, spec in cfg["roles"].items():
        assert spec.get("model"), f"role {role} has no model"
        assert spec.get("max_tokens"), f"role {role} has no max_tokens"


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
        if spec["model"] in reasoning:
            assert spec["max_tokens"] >= 4096, (
                f"role {role} uses reasoning model {spec['model']} with only "
                f"{spec['max_tokens']} max_tokens; measured need is >= 4096"
            )


def test_response_handling_declares_the_null_content_case() -> None:
    cfg = yaml.safe_load(CONFIG.read_text(encoding="utf-8"))
    handling = cfg["response_handling"]
    assert handling["content_may_be_null"] is True
    assert handling["treat_length_finish_as_error"] is True
    assert handling["strip_code_fences"] is True


# --- routing --------------------------------------------------------------


def test_roles_resolve_to_models(client: LlmClient) -> None:
    for role in client.roles:
        assert client.model_for(role).startswith("ais3/")


def test_unknown_role_is_rejected(client: LlmClient) -> None:
    with pytest.raises(LlmError, match="unknown role"):
        client.model_for("does_not_exist")


def test_excluded_model_cannot_be_routed_to(tmp_path: Path) -> None:
    """llama-guard-3-8b is a safety classifier, not part of this pipeline."""
    cfg = yaml.safe_load(CONFIG.read_text(encoding="utf-8"))
    cfg["roles"]["triage"]["model"] = "ais3/llama-guard-3-8b"
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
