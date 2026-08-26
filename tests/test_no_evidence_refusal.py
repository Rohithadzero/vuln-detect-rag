"""The sharded reader must refuse when no shard finds relevant evidence.

Regression test for the failure that let three absent-CVE control questions be
answered from parametric memory: run() logged "none relevant" and then fell
through to the reduce step anyway. The reduce prompt opens with an
"EVIDENCE EXTRACTED FROM THE RETRIEVED DOCUMENTS" header and closes with
"Answer using only the evidence above", so an empty evidence block tells the
model evidence exists and invites it to supply some. Answers came back opening
"Based on the provided evidence, CVE-2014-0160 is ... Heartbleed", about a CVE
that was deliberately absent from the corpus.

These tests use fake clients and make no network calls.
"""
import re

from rag_assistant.chains.map_reduce import ShardedReader, NO_EVIDENCE_ANSWER
from rag_assistant.llm_config import LLMResult

REFUSAL_MARKERS = ("does not contain", "no information", "not available",
                   "no relevant", "no matching", "no entry", "not found in")


class _Cfg:
    provider = "fake"
    model = "fake-1"


class _Client:
    """Fake provider. Returns `shard_reply` for map calls, records reduce calls."""

    def __init__(self, shard_replies):
        self.config = _Cfg()
        self.shard_replies = list(shard_replies)
        self.reduce_calls = 0
        self.map_calls = 0

    def generate_detailed(self, prompt, **kwargs):
        if "EVIDENCE EXTRACTED" in prompt:
            self.reduce_calls += 1
            return LLMResult(text="Heartbleed is a flaw in OpenSSL's heartbeat "
                                  "extension permitting memory disclosure.",
                             model="fake-1", provider="fake")
        reply = self.shard_replies[min(self.map_calls, len(self.shard_replies) - 1)]
        self.map_calls += 1
        return LLMResult(text=reply, model="fake-1", provider="fake")


def _run(replies, question="What is CVE-2014-0160 and how do I fix it?"):
    client = _Client(replies)
    reader = ShardedReader([client], fallback=None)
    outcome = reader.run(question, ["irrelevant document text"] * 3)
    return client, outcome


def test_refuses_when_every_shard_is_irrelevant():
    client, outcome = _run(["NOTHING_RELEVANT"])
    assert outcome.result.text == NO_EVIDENCE_ANSWER
    assert outcome.result.provider == "map_reduce(no_evidence)"


def test_reduce_is_never_called_without_evidence():
    """The point of the fix: no model ever sees an empty evidence block."""
    client, _ = _run(["NOTHING_RELEVANT"])
    assert client.reduce_calls == 0


def test_refusal_names_no_cve():
    _, outcome = _run(["NOTHING_RELEVANT"])
    assert not re.search(r"CVE-\d{4}-\d{4,}", outcome.result.text)


def test_refusal_is_recognised_by_the_refusal_metric():
    _, outcome = _run(["NOTHING_RELEVANT"])
    body = outcome.result.text.lower()
    assert any(marker in body for marker in REFUSAL_MARKERS)


def test_reduce_still_runs_when_one_shard_has_evidence():
    """Guard against over-correcting into refusing on partial evidence."""
    client, outcome = _run(["- affected: openssl 1.0.1 [Doc 1]", "NOTHING_RELEVANT"])
    assert client.reduce_calls == 1
    assert outcome.result.text != NO_EVIDENCE_ANSWER
