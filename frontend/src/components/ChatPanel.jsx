import { useState, useRef, useEffect } from 'react'
import { ArrowUp, Loader2, MessagesSquare } from 'lucide-react'
import { Link } from 'react-router-dom'
import { cx } from './ui'

const SUGGESTIONS = [
  'What is CVE-2021-44228?',
  'How do I remediate Log4Shell?',
  'Critical CVEs affecting Exchange',
  'Attack vectors for Spring4Shell',
]

export default function ChatPanel({ messages, onSend, loading }) {
  const [input, setInput] = useState('')
  const endRef = useRef(null)

  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: 'smooth', block: 'end' })
  }, [messages, loading])

  const handleSubmit = (e) => {
    e.preventDefault()
    if (!input.trim() || loading) return
    onSend(input.trim())
    setInput('')
  }

  return (
    <>
      <div className="flex-1 overflow-auto px-4 sm:px-6 py-6" aria-live="polite">
        {messages.length === 0 && !loading && (
          <div className="h-full flex flex-col items-center justify-center text-center">
            <div className="w-10 h-10 rounded-ctl bg-sunken border border-line flex items-center justify-center mb-3">
              <MessagesSquare className="w-5 h-5 text-ink-subtle" aria-hidden="true" />
            </div>
            <p className="text-sm font-medium">Ask about a CVE, a fix, or an exploit</p>
            <p className="text-[13px] text-ink-muted mt-1">Answers cite the documents they came from.</p>
            <div className="flex flex-wrap justify-center gap-2 mt-5 max-w-lg">
              {SUGGESTIONS.map((q) => (
                <button
                  key={q}
                  type="button"
                  onClick={() => onSend(q)}
                  className="h-8 px-3 rounded-full border border-line bg-surface text-[13px] text-ink-muted hover:text-ink hover:border-line-strong transition-colors duration-150"
                >
                  {q}
                </button>
              ))}
            </div>
          </div>
        )}

        <div className="space-y-6 max-w-3xl mx-auto">
          {messages.map((msg, i) =>
            msg.role === 'user' ? (
              <div key={i} className="flex justify-end">
                <div className="max-w-[85%] rounded-card rounded-br-md bg-accent-soft px-4 py-2.5 text-sm whitespace-pre-wrap">
                  {msg.content}
                </div>
              </div>
            ) : (
              <div key={i} className="text-sm leading-relaxed">
                <div className={cx('whitespace-pre-wrap max-w-prose', msg.error && 'text-crit')}>{msg.content}</div>
                {msg.sources?.length > 0 && (
                  <div className="mt-3 flex flex-wrap items-center gap-1.5">
                    <span className="text-xs text-ink-subtle mr-1">Sources</span>
                    {msg.sources.map((s, j) =>
                      s.cve_id ? (
                        <Link
                          key={j}
                          to={`/cve/${s.cve_id}`}
                          className="inline-flex items-center gap-1.5 h-6 px-2 rounded-full border border-line bg-sunken text-xs hover:border-line-strong"
                        >
                          <span className="font-mono">{s.cve_id}</span>
                          {typeof s.score === 'number' && <span className="text-ink-subtle tabular">{(s.score * 100).toFixed(0)}%</span>}
                        </Link>
                      ) : (
                        <span key={j} className="inline-flex items-center h-6 px-2 rounded-full border border-line bg-sunken text-xs">Document</span>
                      )
                    )}
                  </div>
                )}
              </div>
            )
          )}

          {loading && (
            <div className="flex items-center gap-2 text-[13px] text-ink-muted" role="status">
              <Loader2 className="w-4 h-4 animate-spin" aria-hidden="true" />
              Retrieving and writing an answer. This can take up to a minute.
            </div>
          )}
          <div ref={endRef} />
        </div>
      </div>

      <form onSubmit={handleSubmit} className="p-3 border-t border-line">
        <div className="max-w-3xl mx-auto flex items-center gap-2 rounded-card border border-line bg-surface pl-4 pr-1.5 py-1.5 focus-within:border-accent focus-within:ring-2 focus-within:ring-accent/25 transition-colors">
          <input
            type="text"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="Ask about vulnerabilities, CVEs, remediation…"
            className="flex-1 min-w-0 bg-transparent text-sm placeholder:text-ink-subtle focus:outline-none focus-visible:outline-none"
            disabled={loading}
            aria-label="Message"
          />
          <button
            type="submit"
            disabled={loading || !input.trim()}
            className="w-8 h-8 rounded-ctl bg-accent text-accent-fg flex items-center justify-center hover:bg-accent-hover disabled:opacity-40 transition-colors"
            aria-label="Send message"
          >
            <ArrowUp className="w-4 h-4" aria-hidden="true" />
          </button>
        </div>
      </form>
    </>
  )
}
