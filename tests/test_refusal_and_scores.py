"""Refusal scoring and CVSS claim extraction.

Both metrics previously failed in BOTH directions, which is why these are
pinned by test. The refusal check scored three 1,000-character answers about
BlueKeep, EternalBlue and Heartbleed as correct refusals because each buried a
hedge mid-paragraph; it then scored four genuine refusals as hallucinations
because they said "do not contain" rather than "does not contain", or replied
with the bare marker. The score extractor read the year out of
"CVSS score for CVE-2019-0708" and warned the reader about a fabricated score
of 20.0 that no model had claimed.
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

from services.evaluators import EvaluatorService
from rag_assistant.chains import grounding

E = EvaluatorService()


def _refusals(*answers):
    return E.evaluate_refusal(list(answers)).details["correct_refusals"]


# --- refusal: things that ARE refusals ------------------------------------

def test_bare_marker_counts_as_refusal():
    assert _refusals("NOTHING_RELEVANT") == 1


def test_do_not_contain_counts_as_refusal():
    """"do not contain" and "does not contain" are the same refusal."""
    assert _refusals("The provided documents do not contain information "
                     "about CVE-2016-5195 (Dirty COW).") == 1


def test_refusal_naming_the_absent_cve_is_still_a_refusal():
    assert _refusals("The evidence does not contain any information regarding "
                     "CVE-2019-0708 (BlueKeep) or its CVSS score.") == 1


def test_deterministic_no_evidence_answer_counts_as_refusal():
    from rag_assistant.chains.map_reduce import NO_EVIDENCE_ANSWER
    assert _refusals(NO_EVIDENCE_ANSWER) == 1


# --- refusal: things that are NOT refusals --------------------------------

def test_hedged_but_answered_is_not_a_refusal():
    """The failure a substring test cannot see: hedge, then answer anyway."""
    answer = ("Based on the provided evidence, CVE-2014-0160 is a known "
              "vulnerability, commonly referred to as the Heartbleed "
              "vulnerability. It is a security flaw in the OpenSSL library. "
              "Note this is not available in the retrieved documents.")
    d = E.evaluate_refusal([answer]).details
    assert d["correct_refusals"] == 0
    assert d["hedged_but_answered"] == 1


def test_describing_the_subject_is_not_a_refusal():
    assert _refusals("CVE-2019-0708 is a remote code execution flaw in RDP. "
                     "No information was retrieved.") == 0


# --- CVSS claim extraction ------------------------------------------------

def test_identifier_year_is_not_read_as_a_score():
    r = grounding.verify_answer(
        "The evidence does not contain the CVSS score for CVE-2019-0708.",
        "unrelated context", 3, "What is CVE-2019-0708?")
    assert r.unsupported_scores == []
    assert r.claims_checked == 0


def test_impossible_score_is_not_a_claim():
    """CVSS is 0.0-10.0; 20.0 is a parse artefact, not an assertion."""
    r = grounding.verify_answer("The CVSS scores 20.0 were noted.",
                                "context", 3, "q")
    assert r.unsupported_scores == []


def test_real_score_present_in_context_is_supported():
    r = grounding.verify_answer("CVSS base score 9.8 (CRITICAL) [Doc 1]",
                                "CVE-2021-44228 CVSS base score 9.8", 3, "q")
    assert r.unsupported_scores == []
    assert r.claims_checked == 1


def test_real_score_absent_from_context_is_flagged():
    r = grounding.verify_answer("CVSS base score 7.5 [Doc 1]",
                                "context without that score", 3, "q")
    assert r.unsupported_scores == ["7.5"]
