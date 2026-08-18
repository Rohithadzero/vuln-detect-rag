import { useState } from 'react'
import { Sparkles, Loader2, AlertTriangle, RefreshCw, Cpu } from 'lucide-react'
import { explainScan } from '../api/client'

/**
 * Final step of the scan flow: the AI explains what the findings mean.
 *
 * Raw CVE tables are exactly the expertise barrier this project exists to
 * remove, so the briefing is written for a competent engineer who is not a
 * security specialist.
 */
export default function ScanExplanation({ scan }) {
  const [explanation, setExplanation] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [question, setQuestion] = useState('')

  const generate = async (customQuestion) => {
    setLoading(true)
    setError('')
    try {
      const { data } = await explainScan(scan.id, customQuestion)
      setExplanation(data)
      if (data.error) setError(data.error)
    } catch (err) {
      setError(err.message || 'Failed to generate an explanation.')
    } finally {
      setLoading(false)
    }
  }

  if (scan.status !== 'completed') {
    return (
      <div className="bg-white border-3 border-black p-8 text-center shadow-neb">
        <Sparkles className="w-8 h-8 mx-auto mb-2 text-gray-400" />
        <p className="font-black uppercase text-gray-500">
          Available once the scan completes
        </p>
      </div>
    )
  }

  return (
    <div className="space-y-4">
      <div className="bg-white border-3 border-black p-5 shadow-neb">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="min-w-0">
            <h3 className="text-lg font-black uppercase flex items-center gap-2">
              <Sparkles className="w-5 h-5" />
              AI Briefing
            </h3>
            <p className="text-xs font-bold text-gray-600 uppercase tracking-wider mt-1">
              Plain-language explanation of {scan.total_vulnerabilities} findings on {scan.target}
            </p>
          </div>
          <button
            onClick={() => generate(question)}
            disabled={loading}
            className="px-4 py-2 bg-neo-purple border-3 border-black text-sm font-black uppercase nb-btn flex items-center gap-2 flex-shrink-0 disabled:opacity-50"
          >
            {loading ? (
              <><Loader2 className="w-4 h-4 animate-spin" /> Analyzing</>
            ) : explanation ? (
              <><RefreshCw className="w-4 h-4" /> Regenerate</>
            ) : (
              <><Sparkles className="w-4 h-4" /> Explain results</>
            )}
          </button>
        </div>

        <div className="mt-4 flex gap-2">
          <input
            type="text"
            value={question}
            onChange={(e) => setQuestion(e.target.value)}
            onKeyDown={(e) => { if (e.key === 'Enter' && !loading) generate(question) }}
            placeholder="Optional: ask something specific about this scan"
            className="flex-1 min-w-0 bg-white border-3 border-black px-3 py-2 text-sm font-mono nb-input"
            disabled={loading}
          />
        </div>
      </div>

      {error && (
        <div className="bg-neo-red text-white border-3 border-black p-4 shadow-neb flex items-start gap-3">
          <AlertTriangle className="w-5 h-5 flex-shrink-0 mt-0.5" />
          <div className="min-w-0">
            <p className="font-black uppercase text-sm">Could not generate a briefing</p>
            <p className="text-xs font-bold mt-1 break-words">{error}</p>
          </div>
        </div>
      )}

      {explanation && !error && (
        <div className="bg-white border-3 border-black p-5 shadow-neb space-y-4">
          <div className="prose-sm max-w-none whitespace-pre-wrap text-sm leading-relaxed">
            {explanation.explanation}
          </div>

          <div className="pt-3 border-t-2 border-black/20 flex flex-wrap items-center gap-x-4 gap-y-1 text-[10px] font-bold uppercase text-gray-500">
            {explanation.llm_model && (
              <span className="flex items-center gap-1">
                <Cpu className="w-3 h-3" />
                {explanation.llm_provider} / {explanation.llm_model}
              </span>
            )}
            {explanation.generation_ms > 0 && (
              <span>{(explanation.generation_ms / 1000).toFixed(1)}s</span>
            )}
            <span>{explanation.finding_count} findings analyzed</span>
            {explanation.sources?.length > 0 && (
              <span>{explanation.sources.length} sources retrieved</span>
            )}
          </div>
        </div>
      )}

      {!explanation && !loading && !error && (
        <div className="bg-white border-3 border-black p-8 text-center shadow-neb">
          <Sparkles className="w-8 h-8 mx-auto mb-2 text-gray-400" />
          <p className="font-black uppercase text-gray-500">
            Generate a briefing to see what these findings mean
          </p>
        </div>
      )}
    </div>
  )
}
