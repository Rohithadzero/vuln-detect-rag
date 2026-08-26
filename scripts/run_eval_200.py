"""Run the evaluation over the 200-CVE balanced corpus.

This is a wrapper, not a fork. It imports `scripts/run_eval.py` and redirects
three things before calling its `main()`:

  corpus      -> backend/data/sample_nvd_200.json   (not sample_nvd.json)
  vector store-> backend/data/chroma_200, collection cve_knowledge_200
  results     -> backend/data/eval_results_200.json

Nothing that produced the published pilot numbers is touched. `sample_nvd.json`,
the `chroma` directory and `eval_results_v2.json` are left exactly as they are,
so the draft-2 and draft-3 figures stay reproducible while this runs alongside.

    python run_eval_200.py --condition retrieval     # free, no LLM key needed
    python run_eval_200.py --ablation                # all four arms, needs keys

The retrieval arm needs no API key: embeddings are local (all-MiniLM-L6-v2).
The sharded / full / no_rag arms call cloud providers and need GROQ_API_KEY,
GEMINI_API_KEY and OPENROUTER_API_KEY in the project's .env. VulnShard only
shards when two or more cloud providers are configured; with one key it
silently degrades to single-provider reading and the sharded/full comparison
becomes meaningless, so all three keys matter.
"""
import argparse
import json
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent                                  # repository root
DATA = ROOT / "backend" / "data"
CORPUS_200 = DATA / "sample_nvd_200.json"

# Must be set before backend.config is imported: pydantic BaseSettings reads
# the environment at class-definition time, and rag_engine caches the settings
# values into module state on first import.
os.environ["CHROMA_PERSIST_DIR"] = str(DATA / "chroma_200")
os.environ["CHROMA_COLLECTION"] = "cve_knowledge_200"
os.environ.setdefault("VECTOR_STORE_PATH", str(DATA / "chroma_200"))

sys.path.insert(0, str(ROOT / "backend"))
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))


def seed(corpus_path):
    """Index the 200-CVE corpus into the dedicated collection, once."""
    from services.rag_engine import rag_engine
    from config import settings

    print("vector store : %s" % settings.CHROMA_PERSIST_DIR)
    print("collection   : %s" % settings.CHROMA_COLLECTION)

    with open(corpus_path, encoding="utf-8") as handle:
        entries = json.load(handle)

    existing = 0
    try:
        existing = rag_engine.vector_store.count()
    except Exception:
        pass
    if existing:
        print("already indexed: %d chunks, skipping seed" % existing)
        return existing

    indexed = rag_engine.index_cves(entries)
    print("indexed %d chunks from %d CVEs" % (indexed, len(entries)))
    if not indexed:
        raise SystemExit("nothing indexed; retrieval would return no documents")
    return indexed



def make_resumable(original, checkpoint_path, every=5):
    """Wrap run_eval.run_condition so progress survives an interruption.

    run_eval.py accumulates all 405 records in memory and writes once, at the
    very end. Two runs were stopped part-way and both saved nothing -- the
    second had completed 174 questions. Nothing about the experiment requires
    that fragility: each question is independent, so this executes them one at
    a time through the ORIGINAL function (preserving its exact per-question
    logic, including the RAG_MAP_REDUCE handling it sets per condition) and
    checkpoints the accumulated records every `every` questions.

    Rerunning skips any question already recorded for that condition, so a
    killed run resumes where it stopped instead of restarting.
    """
    import contextlib
    import io as _io

    def load():
        if os.path.exists(checkpoint_path):
            with open(checkpoint_path, encoding="utf-8") as handle:
                return json.load(handle)
        return {}

    def save(state):
        tmp = checkpoint_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as handle:
            json.dump(state, handle)
        os.replace(tmp, checkpoint_path)      # atomic: never a half-written file

    def usable(record, condition):
        """Is this record a real measurement, or the residue of an outage?

        A checkpoint that caches failures is worse than no checkpoint: the
        failed question is skipped forever on resume and silently enters the
        results as a zero-token, zero-latency, empty-answer datapoint. A
        provider outage mid-run would otherwise quietly corrupt the dataset.
        """
        if record.get("error"):
            return False
        if condition == "retrieval":
            return bool(record.get("retrieved_texts"))
        return bool((record.get("answer") or "").strip())

    def wrapper(pipeline, questions, condition, top_k):
        state = load()
        bucket = state.setdefault(condition, {})
        if bucket:
            print("  resuming '%s': %d of %d already recorded"
                  % (condition, len(bucket), len(questions)))

        records, fresh, consecutive_failures = [], 0, 0
        for index, item in enumerate(questions, 1):
            key = item["id"]
            if key in bucket:
                records.append(bucket[key])
                continue

            # The original prints its own "[1/1]" line, which is meaningless
            # when it is handed one question at a time; capture it and re-emit
            # with the real index so the log stays monitorable.
            buffer = _io.StringIO()
            with contextlib.redirect_stdout(buffer):
                produced = original(pipeline, [item], condition, top_k)
            tail = buffer.getvalue().strip().split("...")[-1].strip()
            record = produced[0]

            if usable(record, condition):
                consecutive_failures = 0
                bucket[key] = record          # only good records are cached
                records.append(record)
                fresh += 1
                if fresh % every == 0:
                    save(state)
                print("  [%d/%d] %s ... %s" % (index, len(questions), key, tail),
                      flush=True)
            else:
                consecutive_failures += 1
                print("  [%d/%d] %s ... FAILED (not checkpointed): %s"
                      % (index, len(questions), key,
                         str(record.get("error"))[:110]), flush=True)
                # An outage should stop the run, not be ground through 405
                # times leaving a checkpoint full of holes.
                if consecutive_failures >= 8:
                    save(state)
                    raise SystemExit(
                        "aborting: %d consecutive failures -- provider or "
                        "network outage. Nothing bad was checkpointed; rerun "
                        "to resume from question %d."
                        % (consecutive_failures, index - consecutive_failures + 1))

        save(state)
        return records

    return wrapper


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--condition", default="retrieval",
                        choices=["sharded", "full", "no_rag", "retrieval"])
    parser.add_argument("--ablation", action="store_true")
    parser.add_argument("--limit", type=int, default=200)
    parser.add_argument("--top-k", type=int, default=6,
                        help="6 matches the pilot run, not run_eval's default 5")
    parser.add_argument("--repeats", type=int, default=1)
    parser.add_argument("--question-style", default="both")
    parser.add_argument("--output", default=str(DATA / "eval_results_200.json"))
    parser.add_argument("--checkpoint", default=str(DATA / "eval_200_checkpoint.json"),
                        help="resumable per-question record store")
    args = parser.parse_args()

    if not CORPUS_200.exists():
        raise SystemExit("build the corpus first: python build_corpus_200.py")

    seed(CORPUS_200)

    import run_eval
    # The corpus path is a module constant; point it at the 200-CVE file so the
    # question set, the controls' absence check and the reported corpus size
    # all come from the same place.
    run_eval.run_condition = make_resumable(
        run_eval.run_condition, args.checkpoint)
    run_eval.CORPUS_PATH = CORPUS_200

    argv = ["run_eval",
            "--limit", str(args.limit),
            "--top-k", str(args.top_k),
            "--repeats", str(args.repeats),
            "--question-style", args.question_style,
            "--output", args.output]
    argv += ["--ablation"] if args.ablation else ["--condition", args.condition]
    sys.argv = argv

    print("running: %s" % " ".join(argv[1:]))
    return run_eval.main()


if __name__ == "__main__":
    sys.exit(main())
