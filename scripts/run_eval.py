"""Evaluate the live RAG pipeline and emit results for the research paper.

This replaces an earlier script that computed metrics over hardcoded string
literals: it never called the retriever, the vector store, or the LLM, so its
numbers were fixed constants that could not change no matter what the system
did. Any figure produced by that script is not a measurement and must not be
cited.

What this script does instead
-----------------------------
Every number below comes from executing the real pipeline: embedding the
question, querying ChromaDB, building the prompt, and calling the configured
LLM. Re-running it against a broken retriever or a different model produces
different numbers, which is the property that makes it an experiment.

Conditions (ablation)
---------------------
  sharded    Retrieval + generation, with the retrieved documents split across
             the cloud providers (map-reduce). The system as shipped.
  full       Retrieval + generation, with one provider reading the whole
             context in a single call. The pre-sharding behaviour, kept as the
             comparison baseline for what sharding changes.
  no_rag     Generation only, retrieval disabled. Isolates how much the
             retrieval layer contributes versus the model's parametric memory.
  retrieval  Retrieval only, no LLM call. Fast, deterministic, and enough to
             measure the retriever on its own.

`sharded` and `full` differ ONLY in how the retrieved context is delivered to
the models: identical retrieval, identical documents, identical questions. Any
difference between them is attributable to the reading strategy, which is what
makes the pair a controlled comparison rather than two unrelated runs.

Metrics
-------
Retrieval    hit rate @k, precision@1, MRR — did the right document come back?
Generation   BLEU and ROUGE against the CVE record as reference text.
Groundedness citation rate, and CVE fidelity: does every CVE ID in the answer
             appear in the retrieved context? An ID that does not was invented.
Refusal      on control questions about CVEs deliberately absent from the
             corpus, does the system correctly decline instead of hallucinating?
Cost         per-query retrieval and generation latency, and token counts.
Rate limit   tokens charged to the single busiest provider per question. Free
             tiers are spent per provider, so the aggregate hides the only
             quantity that can actually trip a limit.
Verification the deterministic grounding check applied to each answer:
             fabricated CVE/CWE IDs, fabricated CVSS scores, and citations to
             documents that were never supplied.

Known limitations — state these in the paper
--------------------------------------------
1. The reference answers are the corpus records themselves, not independent
   expert-written answers. BLEU and ROUGE against them measure overlap with the
   source text, not correctness or usefulness. They are a weak proxy and should
   be reported as such until a human-graded set exists.
2. The question set is generated from a template per CVE, so it is uniform in
   phrasing and does not represent how practitioners actually ask questions.
   Critically, the description-based ("semantic") questions are derived from
   the indexed description itself, so they share vocabulary with their target
   document. Near-perfect retrieval on them is expected by construction and is
   NOT evidence of strong semantic search. Independently worded questions are
   required before any retrieval claim can be made.
3. The corpus is 50 CVEs. Retrieval scores on a corpus this small are
   optimistic: there are few distractors.
4. Cloud LLMs are non-deterministic; --repeats measures that variance.

Usage
-----
    python scripts/run_eval.py                       # full, 10 questions
    python scripts/run_eval.py --ablation            # all four conditions
    python scripts/run_eval.py --condition sharded   # sharded reading only
    python scripts/run_eval.py --limit 25 --repeats 3
    python scripts/run_eval.py --condition retrieval # retrieval only, no LLM
"""

import argparse
import json
import logging
import os
import statistics
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend"))
sys.path.insert(0, str(ROOT))

from config import settings  # noqa: E402  (path setup must precede import)
from services.evaluators import evaluator_service  # noqa: E402
from rag_assistant.chains.rag_chain import (  # noqa: E402
    RAGPipeline,
    RAGQuery,
    get_rag_pipeline,
)

logger = logging.getLogger("eval")

CORPUS_PATH = ROOT / "backend" / "data" / "sample_nvd.json"
RESULTS_PATH = ROOT / "backend" / "data" / "eval_results.json"

#: CVEs deliberately absent from sample_nvd.json. Asking about these tests
#: whether the system declines to answer or invents one. Verified absent at
#: load time, so this cannot silently rot if the corpus changes.
CONTROL_CVES = [
    ("CVE-2019-0708", "BlueKeep, Windows RDP pre-auth RCE"),
    ("CVE-2017-0144", "EternalBlue, SMBv1 RCE"),
    ("CVE-2014-0160", "Heartbleed, OpenSSL memory disclosure"),
    ("CVE-2018-7600", "Drupalgeddon2, Drupal RCE"),
    ("CVE-2016-5195", "Dirty COW, Linux kernel privilege escalation"),
]


def load_corpus() -> list[dict]:
    """Load the CVE corpus that backs the knowledge base."""
    with open(CORPUS_PATH, "r", encoding="utf-8") as handle:
        return json.load(handle)


#: Words too generic to identify a vulnerability; stripped when building
#: description-based questions so the query is not dominated by boilerplate.
_STOPWORDS = {
    "the", "a", "an", "and", "or", "in", "on", "to", "of", "for", "with",
    "that", "this", "is", "are", "was", "were", "be", "been", "by", "from",
    "as", "at", "it", "its", "can", "could", "may", "allows", "allow",
    "vulnerability", "vulnerabilities", "attacker", "attackers", "issue",
    "affected", "versions", "version", "via", "when", "which", "not", "has",
}


def _semantic_question(entry: dict) -> str:
    """Build a question that describes a CVE without naming it.

    Questions that contain the CVE ID are answered by exact identifier lookup,
    so retrieval scores on them measure string matching rather than semantic
    search and come out near-perfect regardless of embedding quality. Asking by
    description is what actually exercises the retriever.
    """
    description = (entry.get("description") or "").replace("\n", " ")
    # Keep the leading clause: it names the product and the flaw class.
    head = description.split(".")[0]

    words = [w.strip(",;:()[]\"'") for w in head.split()]
    salient = [
        w for w in words
        if w.lower() not in _STOPWORDS and len(w) > 2 and not w.startswith("CVE-")
    ]
    phrase = " ".join(salient[:14]) or head[:120]
    return f"Which vulnerability involves {phrase}? Explain it and how to fix it."


def build_question_set(corpus: list[dict], limit: int,
                       style: str = "id") -> list[dict]:
    """Build answerable questions, one or two per CVE.

    Selection is deterministic — the corpus is sorted by CVE ID and sampled at
    a fixed stride — so re-running the script evaluates the same items and
    successive runs stay comparable.

    Args:
        corpus: The CVE records backing the knowledge base.
        limit: How many CVEs to draw questions from.
        style: "id" asks by CVE identifier, "semantic" asks by description
            only, "both" produces one of each per CVE.
    """
    ordered = sorted(corpus, key=lambda e: e.get("cve_id", ""))
    if limit >= len(ordered):
        chosen = ordered
    else:
        stride = len(ordered) / limit
        chosen = [ordered[int(i * stride)] for i in range(limit)]

    questions = []
    for entry in chosen:
        cve_id = entry.get("cve_id", "")
        reference = (
            f"{entry.get('description', '')} "
            f"Remediation: {entry.get('solution', '')}"
        ).strip()

        if style in ("id", "both"):
            questions.append({
                "id": cve_id,
                "question": f"What is {cve_id} and how do I remediate it?",
                "expected_cve": cve_id,
                "reference": reference,
                "answerable": True,
                "style": "id",
            })
        if style in ("semantic", "both"):
            questions.append({
                "id": f"{cve_id}[sem]",
                "question": _semantic_question(entry),
                "expected_cve": cve_id,
                "reference": reference,
                "answerable": True,
                "style": "semantic",
            })
    return questions


def build_control_set(corpus: list[dict]) -> list[dict]:
    """Build control questions whose subject is absent from the corpus."""
    present = {e.get("cve_id", "").upper() for e in corpus}
    controls = []
    for cve_id, label in CONTROL_CVES:
        if cve_id.upper() in present:
            # The control is only valid while the CVE is genuinely absent.
            logger.warning("Control %s is in the corpus; skipping it", cve_id)
            continue
        controls.append({
            "id": cve_id,
            "question": f"What is {cve_id} ({label}) and what is its CVSS score?",
            "expected_cve": None,
            "reference": "",
            "answerable": False,
        })
    return controls


#: Which conditions drive the generation pipeline (as opposed to retrieval
#: only), and what each sets RAG_MAP_REDUCE to. `sharded` and `full` are the
#: controlled pair: same retrieval, same documents, different delivery.
SHARDING_BY_CONDITION = {"sharded": "1", "full": "0"}


def run_condition(pipeline: RAGPipeline, questions: list[dict],
                  condition: str, top_k: int) -> list[dict]:
    """Execute every question under one experimental condition."""
    records = []

    # Set before the first query, not per query: map_reduce_enabled() reads the
    # environment on every call, so the condition must own this for the whole
    # run or the two arms of the comparison contaminate each other.
    if condition in SHARDING_BY_CONDITION:
        os.environ["RAG_MAP_REDUCE"] = SHARDING_BY_CONDITION[condition]

    for index, item in enumerate(questions, 1):
        print(f"  [{index}/{len(questions)}] {item['id']} ...", end="", flush=True)
        started = time.perf_counter()

        record: dict = {
            "id": item["id"],
            "question": item["question"],
            "answerable": item["answerable"],
            "expected_cve": item["expected_cve"],
            "style": item.get("style", "id"),
            "condition": condition,
        }

        try:
            if condition == "retrieval":
                # Retrieval only: no LLM call, so this measures the retriever
                # in isolation and runs in milliseconds.
                results = pipeline.retrieve(
                    RAGQuery(question=item["question"], top_k=top_k,
                             conversation_history=False)
                )
                record.update({
                    "answer": "",
                    "retrieved_cves": [
                        (r.metadata or {}).get("cve_id") for r in results
                    ],
                    "retrieved_texts": [r.document.content for r in results],
                    "scores": [round(r.score, 4) for r in results],
                    "retrieval_ms": round((time.perf_counter() - started) * 1000, 1),
                    "generation_ms": 0.0,
                })

            elif condition == "no_rag":
                # Generation with retrieval disabled: what the model knows
                # without the knowledge base. The baseline for the ablation.
                result = pipeline.llm_client.generate_detailed(
                    item["question"],
                    system=(
                        "You are a cybersecurity expert. Answer from your own "
                        "knowledge. State the CVSS score and remediation if you "
                        "know them."
                    ),
                )
                record.update({
                    "answer": result.text,
                    "retrieved_cves": [],
                    "retrieved_texts": [],
                    "scores": [],
                    "retrieval_ms": 0.0,
                    "generation_ms": result.latency_ms,
                    "prompt_tokens": result.prompt_tokens,
                    "completion_tokens": result.completion_tokens,
                    "error": result.error,
                })

            else:  # sharded or full — identical except for RAG_MAP_REDUCE
                response = pipeline.query(
                    RAGQuery(question=item["question"], top_k=top_k,
                             conversation_history=False)
                )
                meta = response.metadata
                reading = meta.get("reading_strategy") or {}
                grounding_report = meta.get("grounding") or {}
                record.update({
                    "reading_strategy": reading.get("strategy"),
                    "shards": reading.get("shards", 0),
                    "shards_with_content": reading.get("shards_with_content", 0),
                    "map_providers": reading.get("map_providers") or [],
                    "tokens_by_provider": reading.get("tokens_by_provider") or {},
                    "peak_provider_tokens": reading.get("peak_provider_tokens", 0),
                    "fell_back": reading.get("fell_back_to_single_call", False),
                    "verified_clean": grounding_report.get("clean"),
                    "verified_support_rate": grounding_report.get("support_rate"),
                    "verified_claims": grounding_report.get("claims_checked", 0),
                    "unsupported_cves": grounding_report.get("unsupported_cves") or [],
                    "unsupported_scores": grounding_report.get("unsupported_scores") or [],
                    "invalid_citations": grounding_report.get("invalid_citations") or [],
                    "answer": response.answer,
                    "grounded": response.grounded,
                    "retrieved_cves": [
                        (s.get("metadata") or {}).get("cve_id")
                        for s in response.sources
                    ],
                    "retrieved_texts": [s.get("content", "") for s in response.sources],
                    "scores": [s.get("score", 0.0) for s in response.sources],
                    "retrieval_ms": meta.get("retrieval_ms", 0.0),
                    "generation_ms": meta.get("generation_ms", 0.0),
                    "prompt_tokens": meta.get("prompt_tokens"),
                    "completion_tokens": meta.get("completion_tokens"),
                    "llm_provider": meta.get("llm_provider"),
                    "llm_model": meta.get("llm_model"),
                    "error": meta.get("error"),
                })

            print(f" {record.get('generation_ms', 0):.0f}ms")

        except Exception as e:
            logger.exception("Question %s failed", item["id"])
            record.update({"answer": "", "error": str(e), "retrieved_cves": [],
                           "retrieved_texts": [], "scores": []})
            print(" FAILED")

        record["reference"] = item["reference"]
        records.append(record)

    return records


def score_records(records: list[dict]) -> dict:
    """Compute every metric over one condition's results."""
    answerable = [r for r in records if r["answerable"]]
    controls = [r for r in records if not r["answerable"]]

    metrics: dict = {}

    # --- Retrieval ---------------------------------------------------------
    if answerable and any(r.get("retrieved_cves") for r in answerable):
        retrieval = evaluator_service.evaluate_retrieval(
            [[c for c in (r.get("retrieved_cves") or []) if c] for r in answerable],
            [r["expected_cve"] for r in answerable],
        )
        metrics["retrieval"] = retrieval.details

        # Broken out by question style: ID-style questions are resolved by
        # exact identifier match, so pooling them with semantic questions
        # inflates the headline number and hides retriever weakness.
        by_style = {}
        for style in ("id", "semantic"):
            subset = [r for r in answerable if r.get("style") == style]
            if subset:
                by_style[style] = evaluator_service.evaluate_retrieval(
                    [[c for c in (r.get("retrieved_cves") or []) if c] for r in subset],
                    [r["expected_cve"] for r in subset],
                ).details
        if len(by_style) > 1:
            metrics["retrieval_by_style"] = by_style

    # --- Generation quality ------------------------------------------------
    scored = [r for r in answerable if r.get("answer") and r.get("reference")]
    if scored:
        bleu_scores, rouge_scores = [], []
        for record in scored:
            bleu_scores.append(
                evaluator_service.evaluate_bleu(record["answer"], record["reference"])
            )
            rouge_scores.append(
                evaluator_service.evaluate_rouge(record["answer"], record["reference"])
            )

        metrics["bleu"] = {
            "mean": round(statistics.fmean(b.score for b in bleu_scores), 4),
            "median": round(statistics.median(b.score for b in bleu_scores), 4),
            "stdev": round(statistics.pstdev([b.score for b in bleu_scores]), 4),
            "bleu_1_mean": round(
                statistics.fmean(b.details["bleu_1"] for b in bleu_scores), 4
            ),
            "n": len(bleu_scores),
        }
        metrics["rouge"] = {
            "mean": round(statistics.fmean(r.score for r in rouge_scores), 4),
            "median": round(statistics.median(r.score for r in rouge_scores), 4),
            "stdev": round(statistics.pstdev([r.score for r in rouge_scores]), 4),
            "rouge_1_f1_mean": round(
                statistics.fmean(r.details["rouge_1"]["f1"] for r in rouge_scores), 4
            ),
            "rouge_l_f1_mean": round(
                statistics.fmean(r.details["rouge_l"]["f1"] for r in rouge_scores), 4
            ),
            "n": len(rouge_scores),
        }

    # --- Groundedness ------------------------------------------------------
    with_answers = [r for r in answerable if r.get("answer")]
    if with_answers:
        grounded = evaluator_service.evaluate_groundedness(
            [r["answer"] for r in with_answers],
            [r.get("retrieved_texts") or [] for r in with_answers],
        )
        metrics["groundedness"] = grounded.details

    # --- Refusal on out-of-corpus questions --------------------------------
    control_answers = [r["answer"] for r in controls if r.get("answer")]
    if control_answers:
        refusal = evaluator_service.evaluate_refusal(control_answers)
        metrics["refusal"] = refusal.details

    # --- Cost --------------------------------------------------------------
    def _mean(key: str, source: list[dict]) -> float:
        values = [r.get(key) or 0 for r in source if r.get(key) is not None]
        return round(statistics.fmean(values), 1) if values else 0.0

    metrics["cost"] = {
        "mean_retrieval_ms": _mean("retrieval_ms", records),
        "mean_generation_ms": _mean("generation_ms", records),
        "mean_prompt_tokens": _mean("prompt_tokens", records),
        "mean_completion_tokens": _mean("completion_tokens", records),
        "queries": len(records),
        "failures": sum(1 for r in records if r.get("error")),
    }

    # --- Rate-limit pressure ----------------------------------------------
    # Free tiers are spent per provider, so the total across the pipeline is
    # not the quantity that trips a limit. What matters is the peak charged to
    # any single endpoint for one question.
    generated = [r for r in records if r.get("answer")]
    if generated:
        peaks, spread = [], []
        for record in generated:
            by_provider = record.get("tokens_by_provider") or {}
            if by_provider:
                peaks.append(max(by_provider.values()))
                spread.append(len(by_provider))
            else:
                # Single-call conditions bill one provider for everything.
                total = (record.get("prompt_tokens") or 0) +                         (record.get("completion_tokens") or 0)
                if total:
                    peaks.append(total)
                    spread.append(1)
        if peaks:
            metrics["rate_limit"] = {
                "mean_peak_provider_tokens": round(statistics.fmean(peaks), 1),
                "max_peak_provider_tokens": max(peaks),
                "mean_providers_per_query": round(statistics.fmean(spread), 2),
                "n": len(peaks),
            }

    # --- Deterministic grounding verification ------------------------------
    verified = [r for r in generated if r.get("verified_support_rate") is not None]
    if verified:
        metrics["verification"] = {
            "mean_support_rate": round(
                statistics.fmean(r["verified_support_rate"] for r in verified), 4
            ),
            "answers_fully_supported": sum(
                1 for r in verified if r.get("verified_clean")
            ),
            "answers_checked": len(verified),
            "total_claims_checked": sum(
                r.get("verified_claims", 0) for r in verified
            ),
            "fabricated_cve_ids": sum(
                len(r.get("unsupported_cves") or []) for r in verified
            ),
            "fabricated_cvss_scores": sum(
                len(r.get("unsupported_scores") or []) for r in verified
            ),
            "citations_to_missing_docs": sum(
                len(r.get("invalid_citations") or []) for r in verified
            ),
        }

    # --- Sharding behaviour -------------------------------------------------
    sharded = [r for r in generated if r.get("reading_strategy") == "sharded"]
    if sharded:
        metrics["sharding"] = {
            "queries_sharded": len(sharded),
            "queries_generated": len(generated),
            "mean_shards": round(
                statistics.fmean(r.get("shards", 0) for r in sharded), 2
            ),
            "mean_shards_with_content": round(
                statistics.fmean(r.get("shards_with_content", 0) for r in sharded), 2
            ),
            "fell_back_to_single_call": sum(
                1 for r in generated if r.get("fell_back")
            ),
            "distinct_providers_seen": sorted({
                p for r in sharded for p in (r.get("map_providers") or [])
            }),
        }

    return metrics


NL = chr(10)


def print_report(all_metrics: dict, environment: dict) -> None:
    """Print a human-readable summary."""
    print("\n" + "=" * 74)
    print("  VulnDetectRAG — Evaluation Results")
    print("=" * 74)
    print(f"  timestamp     : {environment['timestamp']}")
    print(f"  llm provider  : {environment['llm_provider']}")
    print(f"  llm model     : {environment['llm_model']}")
    print(f"  embeddings    : {environment['embedding_model']}")
    print(f"  corpus docs   : {environment['vector_documents']} chunks "
          f"from {environment['corpus_cves']} CVEs")
    print(f"  questions     : {environment['answerable']} answerable, "
          f"{environment['controls']} controls")

    for condition, metrics in all_metrics.items():
        print("\n" + "-" * 74)
        print(f"  CONDITION: {condition}")
        print("-" * 74)

        if "retrieval" in metrics:
            r = metrics["retrieval"]
            print(f"  Retrieval    hit@k={r['hit_rate_at_k']:.4f}  "
                  f"P@1={r['precision_at_1']:.4f}  MRR={r['mrr']:.4f}  "
                  f"({r['hits']}/{r['queries']} found)")
        for style, r in (metrics.get("retrieval_by_style") or {}).items():
            note = " (exact ID match - not a semantic test)" if style == "id" else ""
            print(f"    by style: {style:9} hit@k={r['hit_rate_at_k']:.4f}  "
                  f"P@1={r['precision_at_1']:.4f}  MRR={r['mrr']:.4f}{note}")
        if "bleu" in metrics:
            b = metrics["bleu"]
            print(f"  BLEU         mean={b['mean']:.4f}  median={b['median']:.4f}  "
                  f"sd={b['stdev']:.4f}  BLEU-1={b['bleu_1_mean']:.4f}")
        if "rouge" in metrics:
            g = metrics["rouge"]
            print(f"  ROUGE        mean={g['mean']:.4f}  median={g['median']:.4f}  "
                  f"sd={g['stdev']:.4f}  R-1={g['rouge_1_f1_mean']:.4f}  "
                  f"R-L={g['rouge_l_f1_mean']:.4f}")
        if "groundedness" in metrics:
            d = metrics["groundedness"]
            print(f"  Grounded     citation_rate={d['citation_rate']:.4f}  "
                  f"cve_fidelity={d['cve_fidelity']:.4f}  "
                  f"invented_cves={d['unsupported_cve_mentions']}")
        if "refusal" in metrics:
            f = metrics["refusal"]
            print(f"  Refusal      correct={f['correct_refusals']}/"
                  f"{f['control_questions']}  "
                  f"hallucinated={f['hallucinated_answers']}")
        if "verification" in metrics:
            v = metrics["verification"]
            print(f"  Verified     support_rate={v['mean_support_rate']:.4f}  "
                  f"clean={v['answers_fully_supported']}/{v['answers_checked']}  "
                  f"fake_cves={v['fabricated_cve_ids']}  "
                  f"fake_scores={v['fabricated_cvss_scores']}  "
                  f"bad_cites={v['citations_to_missing_docs']}")
        if "sharding" in metrics:
            sh = metrics["sharding"]
            print(f"  Sharding     {sh['queries_sharded']}/{sh['queries_generated']} "
                  f"queries split  mean_shards={sh['mean_shards']:.2f}  "
                  f"with_content={sh['mean_shards_with_content']:.2f}  "
                  f"fellback={sh['fell_back_to_single_call']}")
            print(f"               providers: "
                  f"{', '.join(sh['distinct_providers_seen']) or 'none'}")
        if "rate_limit" in metrics:
            rl = metrics["rate_limit"]
            print(f"  Rate limit   peak_tokens_on_one_provider="
                  f"{rl['mean_peak_provider_tokens']:.0f} mean / "
                  f"{rl['max_peak_provider_tokens']} max  "
                  f"providers/query={rl['mean_providers_per_query']:.2f}")
        c = metrics["cost"]
        print(f"  Cost         retrieval={c['mean_retrieval_ms']:.1f}ms  "
              f"generation={c['mean_generation_ms']:.1f}ms  "
              f"tokens={c['mean_prompt_tokens']:.0f}/"
              f"{c['mean_completion_tokens']:.0f}  "
              f"failures={c['failures']}")

    if "sharded" in all_metrics and "full" in all_metrics:
        print(NL + "-" * 74)
        print("  ABLATION: what sharded reading changes")
        print("  (identical retrieval and documents; only the delivery differs)")
        print("-" * 74)
        sh, fu = all_metrics["sharded"], all_metrics["full"]
        if "rate_limit" in sh and "rate_limit" in fu:
            a = sh["rate_limit"]["mean_peak_provider_tokens"]
            b = fu["rate_limit"]["mean_peak_provider_tokens"]
            ratio = ("%.2fx lower" % (b / a)) if a else "n/a"
            print(f"  {'Peak tokens/provider':24} sharded={a:.0f}  full={b:.0f}  ({ratio})")
        for label, key, sub in (
            ("Mean support rate", "verification", "mean_support_rate"),
            ("ROUGE mean", "rouge", "mean"),
            ("BLEU mean", "bleu", "mean"),
            ("CVE fidelity", "groundedness", "cve_fidelity"),
        ):
            if key in sh and key in fu:
                a, b = sh[key][sub], fu[key][sub]
                print(f"  {label:24} sharded={a:.4f}  full={b:.4f}  delta={a - b:+.4f}")
        if "verification" in sh and "verification" in fu:
            for label, key in (("Fabricated CVE IDs", "fabricated_cve_ids"),
                               ("Fabricated CVSS scores", "fabricated_cvss_scores")):
                a, b = sh["verification"][key], fu["verification"][key]
                print(f"  {label:24} sharded={a}  full={b}  delta={a - b:+d}")
        print(f"  {'Mean generation ms':24} "
              f"sharded={sh['cost']['mean_generation_ms']:.0f}  "
              f"full={fu['cost']['mean_generation_ms']:.0f}")

    if "full" in all_metrics and "no_rag" in all_metrics:
        print("\n" + "-" * 74)
        print("  ABLATION: what retrieval contributes")
        print("-" * 74)
        full, base = all_metrics["full"], all_metrics["no_rag"]
        for label, key, sub in (
            ("ROUGE mean", "rouge", "mean"),
            ("BLEU mean", "bleu", "mean"),
            ("CVE fidelity", "groundedness", "cve_fidelity"),
        ):
            if key in full and key in base:
                a, b = full[key][sub], base[key][sub]
                delta = a - b
                print(f"  {label:14} full={a:.4f}  no_rag={b:.4f}  "
                      f"delta={delta:+.4f}")
        if "refusal" in full and "refusal" in base:
            print(f"  {'Refusal rate':14} "
                  f"full={full['refusal']['correct_refusals']}/"
                  f"{full['refusal']['control_questions']}  "
                  f"no_rag={base['refusal']['correct_refusals']}/"
                  f"{base['refusal']['control_questions']}")

    print("\n" + "=" * 74)
    print("  Limitations (must be stated alongside these numbers)")
    print("=" * 74)
    print("  - References are the corpus records themselves, not independent")
    print("    expert answers, so BLEU/ROUGE measure source overlap, not")
    print("    correctness. Treat them as a weak proxy.")
    print("  - Questions are template-generated and uniform in phrasing.")
    print("  - ID-style questions are resolved by exact identifier lookup and")
    print("    semantic-style questions are derived from the indexed text, so")
    print("    BOTH are near-perfect by construction. Neither supports a claim")
    print("    of strong retrieval; independently worded questions are needed.")
    print(f"  - The corpus holds {environment['corpus_cves']} CVEs; retrieval")
    print("    scores are optimistic at this scale (few distractors).")
    print("  - Cloud LLM output is non-deterministic; use --repeats for variance.")
    print("  - Token counts come from each provider's own usage reporting and")
    print("    are not directly comparable across providers. The peak-provider")
    print("    figure indicates rate-limit pressure, not exact billing.")
    print("  - The sharded and full arms may be served by different providers")
    print("    and models, because each rotates on rate limits. Differences in")
    print("    ANSWER QUALITY between them are therefore not cleanly")
    print("    attributable to the reading strategy alone. Only the token")
    print("    distribution is a controlled measurement.")
    print("=" * 74)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Evaluate the live VulnDetectRAG pipeline."
    )
    parser.add_argument("--limit", type=int, default=10,
                        help="Answerable questions to evaluate (default 10)")
    parser.add_argument("--top-k", type=int, default=5,
                        help="Documents to retrieve per query (default 5)")
    parser.add_argument("--condition", default="sharded",
                        choices=["sharded", "full", "no_rag", "retrieval"],
                        help="Single condition to run (default sharded)")
    parser.add_argument("--ablation", action="store_true",
                        help="Run all conditions and compare them")
    parser.add_argument("--repeats", type=int, default=1,
                        help="Repeat runs to measure variance (default 1)")
    parser.add_argument("--question-style", default="both",
                        choices=["id", "semantic", "both"],
                        help="Ask by CVE ID, by description only, or both "
                             "(default both). ID-style questions are answered "
                             "by exact identifier lookup, so semantic-style "
                             "questions are the honest test of retrieval.")
    parser.add_argument("--no-controls", action="store_true",
                        help="Skip the out-of-corpus refusal controls")
    parser.add_argument("--output", default=str(RESULTS_PATH),
                        help="Where to write the JSON results")
    args = parser.parse_args()

    logging.basicConfig(level=logging.ERROR,
                        format="%(levelname)s %(name)s: %(message)s")

    corpus = load_corpus()
    questions = build_question_set(corpus, args.limit, args.question_style)
    if not args.no_controls:
        questions += build_control_set(corpus)

    pipeline = get_rag_pipeline("default")
    pipeline.initialize()

    conditions = (["sharded", "full", "no_rag", "retrieval"]
                  if args.ablation else [args.condition])

    # Reported so a result can be tied to the exact configuration that produced
    # it — without this the numbers are not reproducible.
    try:
        llm_provider = pipeline.llm_client.config.provider
        llm_model = pipeline.llm_client.config.model
    except Exception as e:
        llm_provider, llm_model = "unavailable", str(e)[:80]

    environment = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "llm_provider": llm_provider,
        "llm_model": llm_model,
        "embedding_provider": pipeline.embedding_service.provider,
        "embedding_model": pipeline.embedding_service.model,
        "vector_documents": pipeline.vector_store.count(),
        "collection": pipeline.vector_store.collection_name,
        "corpus_cves": len(corpus),
        "answerable": sum(1 for q in questions if q["answerable"]),
        "controls": sum(1 for q in questions if not q["answerable"]),
        "top_k": args.top_k,
        "repeats": args.repeats,
        "app_version": settings.APP_VERSION,
    }

    all_metrics: dict = {}
    all_records: dict = {}

    for condition in conditions:
        print(f"\nRunning condition '{condition}' "
              f"({len(questions)} questions x {args.repeats})")
        runs = []
        for repeat in range(args.repeats):
            if args.repeats > 1:
                print(f"  repeat {repeat + 1}/{args.repeats}")
            runs.extend(run_condition(pipeline, questions, condition, args.top_k))
        all_records[condition] = runs
        all_metrics[condition] = score_records(runs)

    print_report(all_metrics, environment)

    payload = {
        "environment": environment,
        "metrics": all_metrics,
        "records": all_records,
        "limitations": [
            "References are corpus records, not independent expert answers; "
            "BLEU/ROUGE measure overlap with source text, not correctness.",
            "Questions are template-generated and uniform in phrasing.",
            f"Corpus is {len(corpus)} CVEs, so retrieval scores are optimistic.",
            "Semantic questions are derived from the indexed descriptions and "
            "share their vocabulary; high retrieval scores are expected by "
            "construction and do not demonstrate semantic search quality.",
            "Cloud LLM output is non-deterministic.",
        ],
    }
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)
    print(f"\nResults written to {output_path}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
