"""Post-hoc grounding verification for generated answers.

The grounding rules in the system prompt are an instruction, not a guarantee.
A model can be told five times to answer only from the context and still emit a
CVE ID it remembers from pre-training. This module checks the produced answer
against the retrieved text *after* generation, deterministically and without a
model call, and reports every claim that the context does not support.

Only claim types with a low false-positive rate are checked:

  * CVE identifiers    — an exact, unambiguous string; the single most damaging
                         thing to fabricate in this domain
  * CWE identifiers    — same property
  * CVSS scores        — checked only where the answer explicitly labels a
                         number as a CVSS score, so prose numbers are ignored
  * [Doc N] citations  — a citation pointing past the last supplied document is
                         a fabricated provenance claim

Free-text claims (prose descriptions, remediation advice) are deliberately not
checked: any string-matching heuristic over them produces more false alarms
than findings, and a noisy verifier gets ignored.
"""

import logging
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
CWE_PATTERN = re.compile(r"CWE-\d{1,4}", re.IGNORECASE)
CITATION_PATTERN = re.compile(r"\[Doc\s*(\d+)\]", re.IGNORECASE)

#: Dash-like characters models substitute for a plain hyphen. Left unhandled,
#: an answer written "CVE‑2021‑44228" (non-breaking hyphens, which
#: several models emit when formatting identifiers) matches no pattern at all,
#: and the verifier reports a clean answer because it silently checked nothing.
#: Normalizing is therefore not cosmetic: it is what makes the check run.
_DASHES = str.maketrans({
    "‐": "-", "‑": "-", "‒": "-", "–": "-",
    "—": "-", "―": "-", "−": "-", "­": "-",
})


def normalize(text: str) -> str:
    """Fold dash variants to ASCII hyphens so identifiers match."""
    return (text or "").translate(_DASHES)

#: "CVSS 9.8", "CVSS:3.1 score of 9.8", "CVSS score: 7.5", "base score 7.5".
#: The number must be adjacent to an explicit CVSS/base-score label, so a
#: version number or a port in the same sentence is never mistaken for a score.
CVSS_PATTERN = re.compile(
    r"(?:CVSS(?:\s*[:v]?\s*\d\.\d)?|base\s+score)"   # label, optional vector version
    r"[^\d\n]{0,30}"                                  # "score of", ":", " / severity:** ", …
    r"(\d{1,2}(?:\.\d)?)",                            # the score itself
    re.IGNORECASE,
)


@dataclass
class GroundingReport:
    """What the answer claimed that the context does not support."""

    #: CVE IDs asserted in the answer but absent from every retrieved document.
    unsupported_cves: List[str] = field(default_factory=list)
    #: CWE IDs asserted in the answer but absent from the context.
    unsupported_cwes: List[str] = field(default_factory=list)
    #: CVSS scores asserted in the answer but absent from the context.
    unsupported_scores: List[str] = field(default_factory=list)
    #: [Doc N] references pointing past the last document actually supplied.
    invalid_citations: List[int] = field(default_factory=list)
    #: How many [Doc N] citations the answer carried at all.
    citation_count: int = 0
    #: Distinct documents the answer actually drew on.
    documents_cited: int = 0
    #: Documents that were supplied to the model.
    documents_supplied: int = 0
    #: Verifiable claims found, and how many were supported.
    claims_checked: int = 0
    claims_supported: int = 0

    @property
    def clean(self) -> bool:
        """True when nothing in the answer contradicts the supplied context."""
        return not (
            self.unsupported_cves
            or self.unsupported_cwes
            or self.unsupported_scores
            or self.invalid_citations
        )

    @property
    def support_rate(self) -> float:
        """Fraction of checkable claims the context backs up.

        1.0 when there was nothing to check, because an answer that asserts no
        verifiable facts has not fabricated any.
        """
        if not self.claims_checked:
            return 1.0
        return round(self.claims_supported / self.claims_checked, 4)

    @property
    def uncited(self) -> bool:
        """Grounded context was supplied but the answer cited none of it."""
        return self.documents_supplied > 0 and self.citation_count == 0

    def summary(self) -> str:
        """One-line human-readable verdict, for logs."""
        if self.clean and not self.uncited:
            return (
                f"grounded: {self.claims_supported}/{self.claims_checked} claims "
                f"supported, {self.citation_count} citations across "
                f"{self.documents_cited}/{self.documents_supplied} documents"
            )
        problems = []
        if self.unsupported_cves:
            problems.append(f"{len(self.unsupported_cves)} unsupported CVE IDs")
        if self.unsupported_cwes:
            problems.append(f"{len(self.unsupported_cwes)} unsupported CWE IDs")
        if self.unsupported_scores:
            problems.append(f"{len(self.unsupported_scores)} unsupported CVSS scores")
        if self.invalid_citations:
            problems.append(f"citations to missing docs {self.invalid_citations}")
        if self.uncited:
            problems.append("no citations despite supplied context")
        return "ungrounded: " + ", ".join(problems)

    def as_dict(self) -> Dict[str, object]:
        """Flat form for API responses and evaluation records."""
        return {
            'clean': self.clean,
            'support_rate': self.support_rate,
            'claims_checked': self.claims_checked,
            'claims_supported': self.claims_supported,
            'citation_count': self.citation_count,
            'documents_cited': self.documents_cited,
            'documents_supplied': self.documents_supplied,
            'unsupported_cves': self.unsupported_cves,
            'unsupported_cwes': self.unsupported_cwes,
            'unsupported_scores': self.unsupported_scores,
            'invalid_citations': self.invalid_citations,
        }


def _normalized_score(raw: str) -> str:
    """Render a CVSS score canonically so 9 and 9.0 compare equal."""
    try:
        return f"{float(raw):.1f}"
    except (TypeError, ValueError):
        return str(raw)


def _context_scores(context: str) -> set:
    """Every number in the context that could legitimately be a CVSS score.

    Deliberately generous: the context is trusted, so anything numeric in it
    that is in CVSS range counts as supporting evidence. Being generous on this
    side means a flagged score is very likely genuinely invented.
    """
    scores = set()
    for match in re.finditer(r"\b(\d{1,2}(?:\.\d)?)\b", context or ""):
        value = match.group(1)
        try:
            number = float(value)
        except ValueError:
            continue
        if 0.0 <= number <= 10.0:
            scores.add(f"{number:.1f}")
    return scores


def verify_answer(answer: str, context: str,
                  documents_supplied: int = 0) -> GroundingReport:
    """Check an answer's verifiable claims against the retrieved context.

    Args:
        answer: The generated answer text.
        context: Concatenated text of every retrieved document, including the
            metadata headers, since a CVSS score often appears only there.
        documents_supplied: How many [Doc N] blocks were given to the model.

    Returns:
        A report listing unsupported claims. An empty report means every
        checkable claim traced back to the context.
    """
    report = GroundingReport(documents_supplied=documents_supplied)
    answer = normalize(answer)
    context = normalize(context)
    haystack = context.upper()

    for cve in dict.fromkeys(m.upper() for m in CVE_PATTERN.findall(answer)):
        report.claims_checked += 1
        if cve in haystack:
            report.claims_supported += 1
        else:
            report.unsupported_cves.append(cve)

    for cwe in dict.fromkeys(m.upper() for m in CWE_PATTERN.findall(answer)):
        report.claims_checked += 1
        if cwe in haystack:
            report.claims_supported += 1
        else:
            report.unsupported_cwes.append(cwe)

    supported_scores = _context_scores(context)
    for raw in dict.fromkeys(CVSS_PATTERN.findall(answer)):
        score = _normalized_score(raw)
        report.claims_checked += 1
        if score in supported_scores:
            report.claims_supported += 1
        else:
            report.unsupported_scores.append(score)

    cited = [int(n) for n in CITATION_PATTERN.findall(answer)]
    report.citation_count = len(cited)
    report.documents_cited = len({n for n in cited if 1 <= n <= documents_supplied})
    if documents_supplied:
        report.invalid_citations = sorted(
            {n for n in cited if n < 1 or n > documents_supplied}
        )

    return report


#: Appended to an answer whose claims could not all be traced to the context.
#: Shown to the user rather than silently logged: an unverifiable claim the
#: reader believes is worse than a visibly caveated one.
WARNING_TEMPLATE = (
    "\n\n---\n**Grounding check:** {detail} These were not found in the "
    "retrieved documents and may be inaccurate. Verify against the vendor "
    "advisory before acting on them."
)


def annotate(answer: str, report: GroundingReport) -> str:
    """Append a visible caveat when the answer made unsupported claims."""
    if report.clean:
        return answer

    details = []
    if report.unsupported_cves:
        details.append(
            "the identifiers " + ", ".join(report.unsupported_cves[:6])
        )
    if report.unsupported_cwes:
        details.append("the weakness IDs " + ", ".join(report.unsupported_cwes[:6]))
    if report.unsupported_scores:
        details.append(
            "the CVSS scores " + ", ".join(report.unsupported_scores[:6])
        )
    if report.invalid_citations:
        details.append(
            "citations to documents "
            + ", ".join(str(n) for n in report.invalid_citations[:6])
            + " which were not provided"
        )

    if not details:
        return answer

    joined = details[0] if len(details) == 1 else (
        ", ".join(details[:-1]) + " and " + details[-1]
    )
    # Upper-case only the first letter. str.capitalize() would lower-case the
    # rest and mangle the very identifiers being reported.
    joined = joined[0].upper() + joined[1:]
    return answer + WARNING_TEMPLATE.format(detail=joined + ".")


#: System prompt for the optional single corrective pass.
REPAIR_SYSTEM = """You are correcting a security answer that cited facts absent from its evidence.

Rules:
1. Remove every claim built on the unsupported items listed below. Delete the
   sentence if the claim is the whole sentence.
2. Change nothing else. Keep the wording, structure and [Doc N] citations of
   every supported claim exactly as they are.
3. Do not substitute a different CVE ID, score, or version for a removed one.
   If a value is unknown, say it is not available in the retrieved documents.
4. If removing the unsupported claims empties the answer, say plainly that the
   knowledge base has no matching entry.
5. Output only the corrected answer. Never mention this correction step."""


def build_repair_prompt(answer: str, report: GroundingReport) -> Optional[str]:
    """Build the corrective prompt, or None when nothing needs repairing.

    Repair costs one extra LLM call, so it is only worth doing for fabricated
    identifiers and scores — the failures that mislead a reader into patching
    the wrong thing. A stray citation number is annotated, not repaired.
    """
    unsupported = (
        report.unsupported_cves + report.unsupported_cwes + report.unsupported_scores
    )
    if not unsupported:
        return None

    return (
        "The following items appear in the answer below but are NOT present in "
        "the evidence that was retrieved:\n"
        + "\n".join(f"  - {item}" for item in unsupported)
        + "\n\n=== ANSWER TO CORRECT ===\n"
        + answer
    )
