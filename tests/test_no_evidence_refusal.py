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


# ---------------------------------------------------------------------------
# ShardExtract.useful — mixed shards must not be discarded wholesale
# ---------------------------------------------------------------------------

from rag_assistant.chains.map_reduce import ShardExtract, ContextShard


def _extract(text):
    return ShardExtract(shard=ContextShard(0, ["doc"], [1]),
                        provider="fake", model="fake-1", text=text)


def test_bare_marker_is_not_useful():
    assert _extract("NOTHING_RELEVANT").useful is False


def test_mixed_shard_keeps_its_evidence():
    """One irrelevant document must not discard the shard's real findings.

    This is the defect that sent 246 answerable questions to the reduce step
    with no evidence: `useful` tested for the marker as a substring, so an
    extract annotated per document was thrown away along with its evidence.
    """
    e = _extract("- [Doc 1] CVE-2020-18900 heap-based buffer overflow, CVSS 3.3\n"
                 "- [Doc 2] NOTHING_RELEVANT")
    assert e.useful is True
    assert "CVE-2020-18900" in e.content
    assert "NOTHING_RELEVANT" not in e.content


def test_marker_lines_are_stripped_from_content():
    e = _extract("- [Doc 1] NOTHING_RELEVANT\n- [Doc 2] real finding [Doc 2]")
    assert e.content == "- [Doc 2] real finding [Doc 2]"


def test_errored_extract_is_never_useful():
    e = _extract("- [Doc 1] something")
    e.error = "429 rate limited"
    assert e.useful is False


def test_whitespace_only_extract_is_not_useful():
    assert _extract("   \n  \n").useful is False


# ---------------------------------------------------------------------------
# Refusal must require a COMPLETE read, not merely an empty one
# ---------------------------------------------------------------------------

class _PartialFailureClient:
    """One shard errors; the rest legitimately hold nothing relevant.

    This is the shape that produced 134 false refusals (33% of answerable
    questions): shards are dealt one per provider, so a single failing
    provider loses whichever shard it was given. When that is the shard
    holding the answer, the surviving shards correctly report
    NOTHING_RELEVANT and the query used to refuse a question it could have
    answered.
    """

    def __init__(self):
        self.config = _Cfg()
        self.calls = 0

    def generate_detailed(self, prompt, **kwargs):
        if "EVIDENCE EXTRACTED" in prompt:
            return LLMResult(text="reduced", model="fake-1", provider="fake")
        self.calls += 1
        if self.calls == 1:
            raise RuntimeError("410 Client Error: Gone")
        return LLMResult(text="NOTHING_RELEVANT", model="fake-1", provider="fake")


class _Fallback:
    config = _Cfg()
    used = False

    def generate_detailed(self, prompt, **kwargs):
        _Fallback.used = True
        return LLMResult(text="answer from the whole context",
                         model="fake-1", provider="fake")


def test_partial_shard_failure_falls_back_instead_of_refusing():
    _Fallback.used = False
    fb = _Fallback()
    reader = ShardedReader([_PartialFailureClient()], fallback=fb)
    outcome = reader.run("What is CVE-2021-38894?", ["doc a", "doc b", "doc c"])
    assert outcome.result.text != NO_EVIDENCE_ANSWER, \
        "a shard that could not be read must not produce a refusal"
    assert _Fallback.used is True


def test_clean_read_with_nothing_relevant_still_refuses():
    """The refusal path must survive: no failures, genuinely nothing there."""
    client, outcome = _run(["NOTHING_RELEVANT"])
    assert outcome.result.text == NO_EVIDENCE_ANSWER


def test_instruction_quoted_alongside_evidence_is_kept():
    """A model that echoes the instruction must not lose its evidence.

    openrouter/free returns single-line deliberation that quotes the prompt
    back -- 'Reply NOTHING_RELEVANT if the ...' -- in the same line as its
    findings. Line-based stripping on single-line output is all-or-nothing, so
    the marker has to be judged on what removing it leaves behind.
    """
    e = _extract('The docs give CVE-2021-38894 in IBM Security Verify Access '
                 '10.0.0, CVSS 2.7, CWE-209. The instruction said "Reply '
                 'NOTHING_RELEVANT if they provide none" but they do provide '
                 'evidence [Doc 1].')
    assert e.useful is True
    assert "CVE-2021-38894" in e.content


def test_bare_marker_with_doc_reference_is_still_a_marker():
    e = _extract("- [Doc 2] NOTHING_RELEVANT")
    assert e.content == ""
    assert e.useful is False
