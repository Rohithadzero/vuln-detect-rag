import { useState, useEffect } from 'react'
import { BarChart3, AlertTriangle, RefreshCw } from 'lucide-react'
import { getEvalMetrics } from '../api/client'
import { SkeletonRegion, SkeletonCard } from './Skeleton'
import { Callout, Card, CardHeader, EmptyState, IconButton, cx } from './ui'

/**
 * Evaluation results from the last `scripts/run_eval.py` run. Shows only what
 * was measured: with no run, it says so instead of rendering zeros that read
 * as real scores.
 */
export default function MetricsPanel() {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)

  const load = async () => {
    setLoading(true)
    try {
      const res = await getEvalMetrics()
      setData(res.data)
    } catch (err) {
      setData({ available: false, message: err.message })
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [])

  if (loading) {
    return <SkeletonRegion label="Loading metrics"><SkeletonCard lines={4} /></SkeletonRegion>
  }

  if (!data?.available) {
    return (
      <Card>
        <EmptyState icon={BarChart3} title="No evaluation results">{data?.message}</EmptyState>
      </Card>
    )
  }

  const full = data.metrics.full || {}
  const noRag = data.metrics.no_rag || {}
  const env = data.environment || {}

  const rows = [
    ['ROUGE (mean)', full.rouge?.mean, noRag.rouge?.mean],
    ['BLEU (mean)', full.bleu?.mean, noRag.bleu?.mean],
    ['CVE fidelity', full.groundedness?.cve_fidelity, noRag.groundedness?.cve_fidelity],
    ['Citation rate', full.groundedness?.citation_rate, noRag.groundedness?.citation_rate],
  ].filter(([, a]) => a !== undefined)

  const fmt = (v) => (v === undefined || v === null ? '–' : Number(v).toFixed(4))

  return (
    <>
      <Card>
        <CardHeader
          title="RAG versus no retrieval"
          description={`${env.llm_provider}/${env.llm_model} · ${env.embedding_model} · ${env.vector_documents} chunks from ${env.corpus_cves} CVEs · ${env.answerable} questions, ${env.controls} controls`}
          actions={<IconButton size="sm" icon={RefreshCw} label="Reload results" onClick={load} />}
        />
        {rows.length > 0 && (
          <div className="overflow-x-auto border-t border-line">
            <table className="w-full text-[13px]">
              <thead>
                <tr className="bg-sunken text-xs text-ink-subtle">
                  <th scope="col" className="text-left font-normal px-5 py-2">Metric</th>
                  <th scope="col" className="text-right font-normal px-5 py-2">Full RAG</th>
                  <th scope="col" className="text-right font-normal px-5 py-2">No retrieval</th>
                  <th scope="col" className="text-right font-normal px-5 py-2">Change</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-line">
                {rows.map(([label, a, b]) => {
                  const delta = b === undefined ? null : a - b
                  return (
                    <tr key={label}>
                      <th scope="row" className="text-left font-normal px-5 py-2.5">{label}</th>
                      <td className="text-right font-mono tabular font-medium px-5 py-2.5">{fmt(a)}</td>
                      <td className="text-right font-mono tabular text-ink-muted px-5 py-2.5">{fmt(b)}</td>
                      <td className={cx('text-right font-mono tabular px-5 py-2.5', delta > 0 && 'text-ok', delta < 0 && 'text-crit')}>
                        {delta === null ? '–' : `${delta >= 0 ? '+' : ''}${delta.toFixed(4)}`}
                      </td>
                    </tr>
                  )
                })}
                {full.refusal && (
                  <tr>
                    <th scope="row" className="text-left font-normal px-5 py-2.5">Correct refusals</th>
                    <td className="text-right font-mono tabular font-medium px-5 py-2.5">
                      {full.refusal.correct_refusals}/{full.refusal.control_questions}
                    </td>
                    <td className="text-right font-mono tabular text-ink-muted px-5 py-2.5">
                      {noRag.refusal ? `${noRag.refusal.correct_refusals}/${noRag.refusal.control_questions}` : '–'}
                    </td>
                    <td />
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        )}
        {full.cost && (
          <p className="px-5 py-3 border-t border-line text-xs text-ink-subtle tabular">
            Retrieval {full.cost.mean_retrieval_ms} ms · generation {(full.cost.mean_generation_ms / 1000).toFixed(1)} s ·
            tokens {full.cost.mean_prompt_tokens} in / {full.cost.mean_completion_tokens} out
          </p>
        )}
      </Card>

      {data.limitations?.length > 0 && (
        <Callout tone="warn" icon={AlertTriangle} title="Limitations to cite alongside these numbers">
          <ul className="list-disc pl-4 space-y-1 mt-1">
            {data.limitations.map((l, i) => <li key={i}>{l}</li>)}
          </ul>
        </Callout>
      )}
    </>
  )
}
