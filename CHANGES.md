# CHANGES

A record of what was measured, what was found to be wrong, and what each fix
changed. Written because several published numbers in this project turned out
to be artefacts of defects rather than properties of the system, and the
correction is more useful than the original claim.

Dated 2026-08-27. Every number below is measured, not estimated.

---

## Summary

The 200-CVE evaluation was run, audited, and re-run three times. Nine defects
were found. Four were in the product, five were in the measurement harness. The
headline efficiency claim survived every correction and got stronger; four
quality claims moved, and one safety claim was found to be false.

| | Before the audit | After |
|---|---|---|
| Peak-load reduction (sharded vs broadcast) | 5.3x (pilot) | **9.0x** |
| Queries reaching the model with no evidence | 62% | **3.0%** |
| Fabricated CVE IDs (of 400) | 7 | **0** |
| CVE fidelity | 0.9875 | **1.0000** |
| Citation rate | 0.2675 | **0.8475** |
| Grounding support, non-vacuous | 0.9260 | **0.9905** |
| Genuine refusals on absent-CVE controls | 2 / 5 | **5 / 5** |
| Queries merging 2+ shard extracts | 0 | **230 (57.5%)** |

---

## What changed in the published claims

Numbers that were live in the README and are now corrected.

| Claim as published | Corrected | Why |
|---|---|---|
| Retrieval hit@k = 1.0000 | 0.9875; description-style P@1 0.8850 | The pilot's perfect score was a 50-record small-corpus artefact |
| Peak-load reduction 5.3x | 9.0x | Measured at 200 CVEs across 405 paired queries |
| Latency 5.9x faster | 2.0x on medians | The 5.9x was a mean inflated by a censored record; the gap also narrows with corpus size |
| Grounding support 0.9722 | 0.9905 non-vacuous | Zero-claim answers were scored 1.0 — a vacuous pass |
| Citation rate 0.2675 | 0.8475 | The low figure was the empty-evidence defect, not a property of sharding |
| Fabricated CVE IDs: 7 | 0 | All seven came from queries that reached the model with no evidence |
| "Refusals stayed perfect, zero hallucinated answers" | Was **2/5** when written; now genuinely 5/5 | The refusal metric was matching hedge phrases, not judging content |
| "Sharding produces thin answers — thinness measured twice" | Withdrawn | The explanation was wrong. 63% of answers were generated with no evidence at all |
| "four free cloud providers" | Three in the default rotation | OpenRouter's free tier draws on a rate-limited upstream shared pool |

---

## Defects found

### Product defects

**1. The sharded reader answered from parametric memory when it had no evidence.**
`ShardedReader.run` logged "none relevant" and then fell through to the reduce
step anyway. `_reduce_prompt` emits a fixed header — `=== EVIDENCE EXTRACTED
FROM THE RETRIEVED DOCUMENTS ===` — and a trailing "Answer using only the
evidence above", so with zero extracts the model received a prompt asserting
that evidence existed with nothing beneath the header. It answered from memory,
opening "Based on the provided evidence, CVE-2014-0160 is … Heartbleed" about a
CVE deliberately absent from the corpus.

The comment above that branch already said "say so rather than inventing
coverage". The intent had been written down and never implemented.

*Fixed:* return a deterministic refusal before the reduce call. No model is
consulted, so it cannot hallucinate, spends no reduce tokens, and cannot
regress when providers rotate.

**2. A mixed shard discarded its own evidence.**
`ShardExtract.useful` tested for `NOTHING_RELEVANT` as a substring. A shard
holding one relevant document beside two irrelevant ones gets annotated per
document — real evidence on one line, the marker on the next — and that was
enough to discard the whole extract. 250 of 400 answerable questions recorded
`shards_with_content = 0`; in 246 of them retrieval had already found the
correct CVE.

*Fixed:* judge what survives marker removal, and only treat a line as a marker
when removing the marker leaves nothing substantive behind.

**3. A failed shard produced a false refusal.**
Once defect 1 was fixed, the refusal fired whenever no shard returned usable
evidence — including when a shard had *errored*. Absence of evidence in the
shards that were read says nothing about the shard that was not. Shards are
dealt one per provider, so a single failing provider loses exactly one shard of
three, making the answer unreadable on about a third of queries: 134 false
refusals across 400 answerable questions.

*Fixed:* fall back to a single call over the whole context when any shard
failed, and refuse only when every shard was read cleanly.

**4. CVE years were parsed as CVSS scores, producing false caveats.**
`CVSS_PATTERN` allows up to 30 non-digit characters between the label and the
number, so "the CVSS score for CVE-2019-0708" captured `20`. Answers carried an
appended warning — "The CVSS scores 20.0. These were not found in the retrieved
documents and may be inaccurate" — about a score no model had claimed. Every
unsupported score both arms reported was one of these: 20.0 or 60.0.

*Fixed:* blank identifiers before matching, and reject values outside CVSS's
defined 0.0–10.0 range as parse artefacts.

**5. The refusal marker reached the user as the answer.**
Three controls returned the literal string `NOTHING_RELEVANT`. An extract that
survives as "marker plus commentary" is usable, so the reduce step runs, and
with nothing substantive to merge it echoes the marker back.

*Fixed:* substitute the proper refusal sentence when the reduce output is
nothing but the marker.

### Measurement defects

**6. Grounding scored empty answers as perfect.**
`mean_support_rate` is supported-claims over extracted-claims. With zero claims
the ratio is undefined and 1.0 was recorded — a vacuous pass. One answer scored
a perfect grounding rate on a single zero-width space. At 200 CVEs 62% of
sharded answers extracted zero claims, so the average was dominated by vacuous
passes.

*Status:* disclosed, both denominators reported. Once defects 1 and 2 were
fixed the zero-claim rate fell to 9.4%, so the distortion is now small.

**7. The refusal metric failed in both directions.**
`evaluate_refusal` substring-matched a fixed phrase list. It scored three
1,000-character answers about BlueKeep, EternalBlue and Heartbleed as correct
refusals because each buried a hedge mid-paragraph. After the product fixes it
then scored four *genuine* refusals as hallucinations, because they said "do
not contain" rather than "does not contain", or replied with the bare marker,
or said "is unavailable".

*Fixed:* judge what the answer supplies. An answer is a refusal when it
declines **and** does not go on to describe the subject or state a score for
it. Validated against 20 hand-labelled control answers drawn from four separate
runs; all four sets match.

**8. CVE fidelity was scored against truncated documents.**
`run_eval.py` passed `retrieved_texts` to the groundedness evaluator. That field
is the API's `sources` payload, which `rag_engine.py` truncates to 300
characters per document. Any identifier past the cut read as invented, and
identifiers the question itself named were counted too. The broadcast arm
scored 0.7625 against a true 0.9950.

*Fixed:* prefer the per-record verdict from `rag_chain.py`, which already
verifies against the full context, and keep the truncated figure alongside as
`cve_fidelity_truncated_context` rather than silently redefining the metric.

**9. Aggregation aborted after a completed run.**
`evaluate_bleu` returns `{"error": "Empty tokens"}` with no n-gram keys when
either side tokenises to nothing, and the aggregator indexed `details["bleu_1"]`
directly. The guard admitted any truthy answer, and one broadcast answer is a
single zero-width space — truthy, tokenises to nothing. `KeyError` was raised
after all 405 questions had been generated, losing the entire aggregation. Only
the checkpoint saved the run.

*Fixed:* admit records on surviving tokenisation rather than on being
non-empty, tolerate an error result in the n-gram lookups, and report excluded
answers instead of passing them silently.

A tenth issue was cosmetic but biased: the citation-rate regex matched only
ASCII `[Doc N]`, while groq's gpt-oss models cite as `【Doc 1】` and write
identifiers with non-breaking hyphens. It was undercounting one provider's
citations specifically.

---

## Provider configuration

Two of the four configured providers were pointed at models that no longer
exist, which is what lost a shard on roughly a third of sharded queries.

| Provider | Was | Now | Why |
|---|---|---|---|
| openrouter | `openai/gpt-oss-20b:free` | `minimax/minimax-m3:free` | The model was retired and is absent from OpenRouter's catalogue entirely, so the client's free-model check correctly refused it |
| nvidia | `meta/llama-3.3-70b-instruct` | `nvidia/nemotron-3-nano-30b-a3b` | Returns 410 Gone; most of NVIDIA's catalogue returns 404 for this key |
| gemini | `gemini-flash-latest` | `gemini-3.1-flash-lite-preview` | The configured model returns 503, and `gemini-3.5-flash`/`-lite` return free-tier 429s. Pinning also removes the model-rotation confound |

Replacements were selected against the real map prompt over three runs each
with a negative control, not by reputation. Rejected: `nemotron-3-super-120b`
(useful output but drops the CVE ID), the nemotron reasoning models (emit
chain-of-thought, 12–28 s), `minimax-m2.7` and `gemma-4` (429 upstream), and
several that return empty strings.

**OpenRouter is dropped from the default rotation.** Its 429s carry
`limit_source: upstream_provider_shared_pool` — the upstream provider's shared
free pool, not the account — so another key would not help. Separately the
account's own free-model cap of 50 requests/day cannot cover the ~135 calls a
405-question run deals it. The pinned model stays configured for whenever
credits exist.

---

## What the evaluation now shows

Sharding is a **large, reproducible efficiency win at no measurable cost in
grounding**. It is not an improvement in answer quality, and the data does not
support claiming one:

- Citation rate is identical between the arms to four decimal places.
- Grounding support differs by 0.0014.
- Both arms refuse all five absent-CVE controls with zero hallucinated answers.
- Sharding fabricates 0 CVE identifiers against broadcast's 2, out of 400 — too
  small to claim an effect from.

Fabrication was already near the floor once retrieval worked, so this question
set cannot distinguish a reading strategy robust to fabrication pressure from
one never tested under it.

One property is new and is architectural rather than measured: when every shard
reports no relevant evidence and none failed to be read, **the sharded path
refuses without calling a model at all**. Both arms score 5/5 on the controls;
only one of them scores 5/5 by construction.

---

## Reproducibility

- The pre-audit results are preserved in `backend/data/prefix_backup/` and the
  intermediate stage in `backend/data/stage2_backup/`, so every before/after
  comparison above can be recomputed.
- The pilot's corpus, vector store and results (`sample_nvd.json`,
  `backend/data/chroma/`, `eval_results_v2.json`) were never modified.
- Provider probe transcripts are in `VDR_revision_plan/provider_probe_2026-08-27/`.
- Regression tests covering the refusal path, marker handling and score
  extraction are in `tests/`.

## Known limitations

- **Model rotation persists.** 130 of 405 sharded records ran on a smaller
  model that groq rotated to under throttling. Peak-token load is dominated by
  prompt size and is unaffected; answer-quality deltas between the arms are not
  cleanly attributable to the reading strategy alone.
- **Stored `unsupported_scores` are stale.** Records written before defect 4 was
  fixed keep their values — 2 in the sharded arm, 5 in the broadcast arm. All
  seven are the parse artefact; none is a real fabrication. They will clear on
  the next regeneration.
- **The `no_rag` arm has not been run at 200 CVEs.** Its pilot latency is 29%
  censored at the ensemble ceiling and is not usable as a baseline.
- **Questions are template-generated**, so these metrics measure grounding
  against a known-correct record rather than expert-judged usefulness.
- **The three arms disagree on retrieval to the third decimal.** `retrieval`
  and `full` both scored hit@k 0.9875 / P@1 0.9425 / MRR 0.9631; `sharded`
  scored 0.9850 / 0.9400 / 0.9606 over the same 400 questions and the same
  index. Retrieval is meant to be deterministic, so a five-query difference
  across runs is unexplained. Nothing claimed here turns on it, and the
  published tables quote the two runs that agree.
- **`peak_provider_tokens` is 0 on every broadcast record.** The field is
  written per provider by the sharded path only; the broadcast peak is that
  single call's `prompt_tokens + completion_tokens`. Recomputing from the raw
  field yields 0 and reads as a clean sweep for sharding, which it is not.
- **The `refusal` block in `eval_200_full.json` is stale**, as the stored
  `unsupported_scores` are. It predates the metric fix and still reads 3/5.
  Re-scoring the same stored answers with the current evaluator gives 5/5 for
  both arms.
