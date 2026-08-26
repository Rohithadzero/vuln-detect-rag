import { useState, useEffect } from 'react'
import { BarChart3, AlertTriangle, RefreshCw } from 'lucide-react'
import { getEvalMetrics } from '../api/client'
import { SkeletonRegion, SkeletonCard } from './Skeleton'

/**
 * Evaluation results from the last `scripts/run_eval.py` run.
 *
 * Shows only what was actually measured. When no evaluation has been run it
 * says so, rather than rendering zeros that read as real scores — the flaw
 * that made the previous version of this panel misleading.
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
    return (
      <SkeletonRegion label="Loading metrics">
        <SkeletonCard lines={4} />
      </SkeletonRegion>
    )
  }

  if (!data?.available) {
    return (
      <div className="bg-white border-3 border-black p-6 shadow-neb text-center">
        <BarChart3 className="w-8 h-8 mx-auto mb-2 text-gray-400" />
        <p className="font-black uppercase text-gray-500">No evaluation results</p>
        <p className="text-xs font-bold text-gray-500 mt-2 break-words">
          {data?.message}
        </p>
      </div>
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

  const fmt = (v) => (v === undefined || v === null ? '—' : Number(v).toFixed(4))

  return (
    <div className="space-y-4">
      <div className="bg-white border-3 border-black shadow-neb">
        <div className="p-4 border-b-[3px] border-black bg-neo-purple flex items-center justify-between gap-3">
          <h3 className="text-sm font-black uppercase flex items-center gap-2">
            <BarChart3 className="w-4 h-4" />
            Evaluation Results
          </h3>
          <button onClick={load} className="p-1 hover:bg-black/10" title="Reload">
            <RefreshCw className="w-4 h-4" />
          </button>
        </div>

        <div className="p-4 space-y-4">
          <div className="text-[10px] font-bold uppercase text-gray-600 grid grid-cols-2 gap-x-4 gap-y-1">
            <span>Model: {env.llm_provider}/{env.llm_model}</span>
            <span>Embeddings: {env.embedding_model}</span>
            <span>{env.vector_documents} chunks / {env.corpus_cves} CVEs</span>
            <span>{env.answerable} questions, {env.controls} controls</span>
          </div>

          {rows.length > 0 && (
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b-2 border-black">
                    <th className="text-left py-2 font-black uppercase">Metric</th>
                    <th className="text-right py-2 font-black uppercase">Full RAG</th>
                    <th className="text-right py-2 font-black uppercase">No retrieval</th>
                    <th className="text-right py-2 font-black uppercase">Delta</th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map(([label, a, b]) => (
                    <tr key={label} className="border-b border-black/10">
                      <td className="py-2 font-bold">{label}</td>
                      <td className="py-2 text-right font-mono font-bold">{fmt(a)}</td>
                      <td className="py-2 text-right font-mono">{fmt(b)}</td>
                      <td className={`py-2 text-right font-mono font-black ${
                        b !== undefined && a - b > 0 ? 'text-green-700' : ''
                      }`}>
                        {b === undefined ? '—' : `${a - b >= 0 ? '+' : ''}${(a - b).toFixed(4)}`}
                      </td>
                    </tr>
                  ))}
                  {full.refusal && (
                    <tr className="border-b border-black/10">
                      <td className="py-2 font-bold">Correct refusals</td>
                      <td className="py-2 text-right font-mono font-bold">
                        {full.refusal.correct_refusals}/{full.refusal.control_questions}
                      </td>
                      <td className="py-2 text-right font-mono">
                        {noRag.refusal
                          ? `${noRag.refusal.correct_refusals}/${noRag.refusal.control_questions}`
                          : '—'}
                      </td>
                      <td className="py-2" />
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          )}

          {full.cost && (
            <div className="text-[10px] font-bold uppercase text-gray-600">
              Retrieval {full.cost.mean_retrieval_ms}ms · generation{' '}
              {(full.cost.mean_generation_ms / 1000).toFixed(1)}s · tokens{' '}
              {full.cost.mean_prompt_tokens}/{full.cost.mean_completion_tokens}
            </div>
          )}
        </div>
      </div>

      {data.limitations?.length > 0 && (
        <div className="bg-neo-yellow border-3 border-black p-4 shadow-neb">
          <p className="text-xs font-black uppercase flex items-center gap-2 mb-2">
            <AlertTriangle className="w-4 h-4" />
            Limitations — cite these alongside the numbers
          </p>
          <ul className="text-[11px] font-bold space-y-1 list-disc list-inside">
            {data.limitations.map((l, i) => <li key={i}>{l}</li>)}
          </ul>
        </div>
      )}
    </div>
  )
}
