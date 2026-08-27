import math
import re
from collections import Counter
from models.schemas import EvalResult


#: Dash variants some providers emit inside identifiers, folded to ASCII
#: so "CVE‑2021‑38894" matches "CVE-2021-38894".
_DASH_FOLD = {ord(c): "-" for c in "‐‑‒–—−"}


def _fold(text: str) -> str:
    return (text or "").translate(_DASH_FOLD)


class EvaluatorService:
    """Compute evaluation metrics for RAG and scanner outputs."""

    # ------------------------------------------------------------------
    # Retrieval metrics
    #
    # Generation metrics alone cannot tell you whether a RAG system works: a
    # fluent answer built on the wrong documents scores well on BLEU. These
    # measure the retriever directly, against the document that should have
    # been found.
    # ------------------------------------------------------------------

    def evaluate_retrieval(
        self, retrieved_ids: list[list[str]], expected_ids: list[str]
    ) -> EvalResult:
        """Score retrieval quality across a set of queries.

        Args:
            retrieved_ids: Per query, the CVE IDs retrieved in rank order.
            expected_ids: Per query, the CVE ID that should have been retrieved.

        Returns:
            EvalResult with hit rate, MRR, and mean reciprocal position.
        """
        if not expected_ids:
            return EvalResult(metric="Retrieval", score=0.0,
                              details={"error": "No queries"})

        hits = 0
        reciprocal_ranks = []
        top1_hits = 0

        for retrieved, expected in zip(retrieved_ids, expected_ids):
            normalized = [str(r).upper() for r in retrieved]
            target = str(expected).upper()

            if normalized and normalized[0] == target:
                top1_hits += 1

            if target in normalized:
                hits += 1
                # Rank is 1-based: the reciprocal of the first correct position.
                reciprocal_ranks.append(1.0 / (normalized.index(target) + 1))
            else:
                reciprocal_ranks.append(0.0)

        total = len(expected_ids)
        hit_rate = hits / total
        mrr = sum(reciprocal_ranks) / total

        return EvalResult(
            metric="Retrieval",
            score=round(mrr, 4),
            details={
                "hit_rate_at_k": round(hit_rate, 4),
                "precision_at_1": round(top1_hits / total, 4),
                "mrr": round(mrr, 4),
                "queries": total,
                "hits": hits,
                "misses": total - hits,
            },
        )

    def evaluate_groundedness(
        self, answers: list[str], contexts: list[list[str]]
    ) -> EvalResult:
        """Estimate how well answers are supported by retrieved context.

        Two cheap, deterministic signals, chosen because they need no second
        LLM to act as judge:
          - citation rate: does the answer reference [Doc N] as instructed?
          - CVE fidelity: does every CVE ID in the answer appear in the context?
            An ID that is not in the context was invented.
        """
        if not answers:
            return EvalResult(metric="Groundedness", score=0.0,
                              details={"error": "No answers"})

        cited = 0
        clean = 0
        hallucinated_total = 0

        for answer, context_docs in zip(answers, contexts):
            # Fold dash variants before matching. Some providers render
            # identifiers with non-breaking hyphens (CVE‑2021‑38894),
            # which an ASCII-hyphen pattern silently misses.
            answer = _fold(answer)

            # Accept full-width brackets as well as ASCII. groq's gpt-oss
            # models cite as 【Doc 1】, and counting only "[Doc 1]"
            # undercounts their citations.
            if re.search(r"[\[【]\s*Doc\s*\d+\s*[\]】]", answer,
                         re.IGNORECASE):
                cited += 1

            context_blob = _fold(" ".join(context_docs)).upper()
            answer_cves = set(
                c.upper() for c in re.findall(r"CVE-\d{4}-\d{4,}", answer, re.IGNORECASE)
            )
            unsupported = {c for c in answer_cves if c not in context_blob}
            hallucinated_total += len(unsupported)
            if not unsupported:
                clean += 1

        total = len(answers)
        fidelity = clean / total

        return EvalResult(
            metric="Groundedness",
            score=round(fidelity, 4),
            details={
                "citation_rate": round(cited / total, 4),
                "cve_fidelity": round(fidelity, 4),
                "answers_with_unsupported_cves": total - clean,
                "unsupported_cve_mentions": hallucinated_total,
                "answers": total,
            },
        )

    def evaluate_refusal(self, answers: list[str]) -> EvalResult:
        """Measure correct refusal on questions the corpus cannot answer.

        Run against control questions whose subject is deliberately absent from
        the knowledge base. A system that answers these is hallucinating, so a
        high score here is as important as a high score on answerable ones.
        """
        if not answers:
            return EvalResult(metric="Refusal", score=0.0,
                              details={"error": "No answers"})

        refusal_markers = (
            "does not contain", "no information", "not available",
            "not in the provided", "no relevant", "cannot find",
            "does not include", "no entry", "not present", "unable to find",
            "no matching", "not found in",
        )

        refused = sum(
            1 for a in answers
            if any(marker in a.lower() for marker in refusal_markers)
        )

        return EvalResult(
            metric="Refusal",
            score=round(refused / len(answers), 4),
            details={
                "correct_refusals": refused,
                "hallucinated_answers": len(answers) - refused,
                "control_questions": len(answers),
            },
        )

    def evaluate_cve_detection(
        self, predicted: list[str], ground_truth: list[str]
    ) -> EvalResult:
        """Compute precision, recall, F1 for CVE detection."""
        pred_set = set(p.upper() for p in predicted)
        truth_set = set(t.upper() for t in ground_truth)

        tp = len(pred_set & truth_set)
        fp = len(pred_set - truth_set)
        fn = len(truth_set - pred_set)

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = (
            2 * precision * recall / (precision + recall)
            if (precision + recall) > 0
            else 0.0
        )
        detection_rate = tp / len(truth_set) if truth_set else 0.0

        return EvalResult(
            metric="CVE Detection",
            score=round(f1, 4),
            details={
                "detection_rate": round(detection_rate, 4),
                "precision": round(precision, 4),
                "recall": round(recall, 4),
                "f1": round(f1, 4),
                "true_positives": tp,
                "false_positives": fp,
                "false_negatives": fn,
            },
        )

    def evaluate_bleu(self, prediction: str, reference: str) -> EvalResult:
        """Compute BLEU score for RAG answer quality."""
        pred_tokens = self._tokenize(prediction)
        ref_tokens = self._tokenize(reference)

        if not pred_tokens or not ref_tokens:
            return EvalResult(
                metric="BLEU", score=0.0, details={"error": "Empty tokens"}
            )

        # BLEU-1 through BLEU-4
        bleu_scores = []
        for n in range(1, 5):
            pred_ngrams = self._get_ngrams(pred_tokens, n)
            ref_ngrams = self._get_ngrams(ref_tokens, n)

            if not pred_ngrams:
                bleu_scores.append(0.0)
                continue

            clipped = 0
            for ngram, count in pred_ngrams.items():
                clipped += min(count, ref_ngrams.get(ngram, 0))

            precision = clipped / sum(pred_ngrams.values()) if pred_ngrams else 0.0
            bleu_scores.append(precision)

        # Brevity penalty
        bp = min(1.0, len(pred_tokens) / len(ref_tokens)) if ref_tokens else 0.0

        # Geometric mean
        if all(s > 0 for s in bleu_scores):
            geo_mean = math.exp(
                sum(math.log(s) for s in bleu_scores) / len(bleu_scores)
            )
        else:
            geo_mean = 0.0

        bleu = bp * geo_mean

        return EvalResult(
            metric="BLEU",
            score=round(bleu, 4),
            details={
                "bleu_1": round(bleu_scores[0], 4) if len(bleu_scores) > 0 else 0,
                "bleu_2": round(bleu_scores[1], 4) if len(bleu_scores) > 1 else 0,
                "bleu_3": round(bleu_scores[2], 4) if len(bleu_scores) > 2 else 0,
                "bleu_4": round(bleu_scores[3], 4) if len(bleu_scores) > 3 else 0,
                "brevity_penalty": round(bp, 4),
            },
        )

    def evaluate_rouge(self, prediction: str, reference: str) -> EvalResult:
        """Compute ROUGE-1, ROUGE-2, ROUGE-L scores."""
        pred_tokens = self._tokenize(prediction)
        ref_tokens = self._tokenize(reference)

        if not pred_tokens or not ref_tokens:
            return EvalResult(
                metric="ROUGE", score=0.0, details={"error": "Empty tokens"}
            )

        # ROUGE-1
        rouge_1 = self._rouge_n(pred_tokens, ref_tokens, 1)

        # ROUGE-2
        rouge_2 = self._rouge_n(pred_tokens, ref_tokens, 2)

        # ROUGE-L (LCS-based)
        rouge_l = self._rouge_l(pred_tokens, ref_tokens)

        avg_score = (rouge_1["f1"] + rouge_2["f1"] + rouge_l["f1"]) / 3

        return EvalResult(
            metric="ROUGE",
            score=round(avg_score, 4),
            details={
                "rouge_1": rouge_1,
                "rouge_2": rouge_2,
                "rouge_l": rouge_l,
            },
        )

    def _tokenize(self, text: str) -> list[str]:
        return re.findall(r"\w+", text.lower())

    def _get_ngrams(self, tokens: list[str], n: int) -> Counter:
        return Counter(tuple(tokens[i : i + n]) for i in range(len(tokens) - n + 1))

    def _rouge_n(self, pred: list[str], ref: list[str], n: int) -> dict:
        pred_ngrams = self._get_ngrams(pred, n)
        ref_ngrams = self._get_ngrams(ref, n)

        overlap = sum(
            min(pred_ngrams.get(k, 0), ref_ngrams.get(k, 0))
            for k in set(pred_ngrams) | set(ref_ngrams)
        )
        pred_total = sum(pred_ngrams.values())
        ref_total = sum(ref_ngrams.values())

        precision = overlap / pred_total if pred_total > 0 else 0.0
        recall = overlap / ref_total if ref_total > 0 else 0.0
        f1 = (
            2 * precision * recall / (precision + recall)
            if (precision + recall) > 0
            else 0.0
        )

        return {
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
        }

    def _rouge_l(self, pred: list[str], ref: list[str]) -> dict:
        lcs_len = self._lcs_length(pred, ref)
        precision = lcs_len / len(pred) if pred else 0.0
        recall = lcs_len / len(ref) if ref else 0.0
        f1 = (
            2 * precision * recall / (precision + recall)
            if (precision + recall) > 0
            else 0.0
        )

        return {
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
        }

    def _lcs_length(self, a: list[str], b: list[str]) -> int:
        m, n = len(a), len(b)
        dp = [[0] * (n + 1) for _ in range(m + 1)]
        for i in range(1, m + 1):
            for j in range(1, n + 1):
                if a[i - 1] == b[j - 1]:
                    dp[i][j] = dp[i - 1][j - 1] + 1
                else:
                    dp[i][j] = max(dp[i - 1][j], dp[i][j - 1])
        return dp[m][n]


evaluator_service = EvaluatorService()
