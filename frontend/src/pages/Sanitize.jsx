import { useRef, useState } from 'react'
import {
  ShieldCheck, Upload, Link2, FileText, X, AlertTriangle, Check, Copy, Trash2,
} from 'lucide-react'
import { sanitizeFiles, sanitizeLinks } from '../api/client'
import {
  Badge, Button, Callout, Card, CardHeader, EmptyState, IconButton, Label, PageHeader, cx,
} from '../components/ui'

const VERDICT = {
  clean: { tone: 'ok', label: 'Clean' },
  low: { tone: 'low', label: 'Low risk' },
  suspicious: { tone: 'high', label: 'Suspicious' },
  malicious: { tone: 'crit', label: 'Malicious' },
  error: { tone: 'neutral', label: 'Could not read' },
}

const SEVERITY_TONE = { CRITICAL: 'crit', HIGH: 'high', MEDIUM: 'med', LOW: 'low', INFO: 'neutral' }

function formatBytes(n) {
  if (n == null) return ''
  if (n < 1024) return `${n} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`
  return `${(n / (1024 * 1024)).toFixed(1)} MB`
}

function ResultCard({ item }) {
  const verdict = VERDICT[item.verdict] || VERDICT.error
  const Icon = item.kind === 'file' ? FileText : Link2
  return (
    <Card as="article">
      <div className="flex items-start justify-between gap-3 px-5 pt-4 pb-3">
        <div className="min-w-0 flex items-start gap-2.5">
          <Icon className="w-4 h-4 mt-0.5 text-ink-subtle flex-shrink-0" aria-hidden="true" />
          <div className="min-w-0">
            <p className="text-sm font-medium text-ink break-all">{item.name}</p>
            <p className="text-xs text-ink-subtle mt-0.5 tabular">
              {item.detected_type && <span>{item.detected_type}</span>}
              {item.size != null && <span> · {formatBytes(item.size)}</span>}
              {item.indicators.length > 0 && <span> · risk {item.score}/100</span>}
            </p>
          </div>
        </div>
        <Badge tone={verdict.tone} className="flex-shrink-0">{verdict.label}</Badge>
      </div>

      <div className="border-t border-line px-5 py-4 space-y-3">
        {item.indicators.length === 0 ? (
          <p className="text-[13px] text-ink-muted flex items-center gap-1.5">
            <Check className="w-4 h-4 text-ok" aria-hidden="true" /> No threat indicators found.
          </p>
        ) : (
          <ul className="space-y-2">
            {item.indicators.map((ind, i) => (
              <li key={i} className="flex items-start gap-2">
                <Badge tone={SEVERITY_TONE[ind.severity] || 'neutral'} className="flex-shrink-0 mt-0.5">
                  {ind.severity}
                </Badge>
                <span className="min-w-0">
                  <span className="text-[13px] font-medium text-ink">{ind.title}</span>
                  {ind.detail && <span className="block text-xs text-ink-muted">{ind.detail}</span>}
                </span>
              </li>
            ))}
          </ul>
        )}

        {item.sanitized && item.sanitized !== item.name && (
          <div className="rounded-ctl bg-sunken border border-line px-3 py-2">
            <p className="text-xs text-ink-subtle mb-1">Cleaned link</p>
            <div className="flex items-center gap-2">
              <code className="text-[13px] text-ink break-all flex-1 min-w-0">{item.sanitized}</code>
              <IconButton
                size="sm"
                icon={Copy}
                label="Copy cleaned link"
                className="flex-shrink-0"
                onClick={() => navigator.clipboard?.writeText(item.sanitized)}
              />
            </div>
          </div>
        )}

        {item.engines?.virustotal && (
          <p className="text-xs text-ink-subtle tabular">
            VirusTotal: {item.engines.virustotal.malicious} malicious ·{' '}
            {item.engines.virustotal.suspicious} suspicious ·{' '}
            {item.engines.virustotal.harmless} harmless
          </p>
        )}

        {item.sha256 && <p className="text-2xs text-ink-subtle font-mono break-all">SHA-256 {item.sha256}</p>}
        {item.note && <p className="text-2xs text-ink-subtle">{item.note}</p>}
      </div>
    </Card>
  )
}

export default function Sanitize() {
  const [files, setFiles] = useState([])
  const [linkText, setLinkText] = useState('')
  const [dragging, setDragging] = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [results, setResults] = useState(null)
  const inputRef = useRef(null)

  const addFiles = (list) => {
    const incoming = Array.from(list || [])
    if (incoming.length === 0) return
    setFiles((prev) => [...prev, ...incoming].slice(0, 20))
  }

  const removeFile = (idx) => setFiles((prev) => prev.filter((_, i) => i !== idx))

  const onDrop = (e) => {
    e.preventDefault()
    setDragging(false)
    addFiles(e.dataTransfer.files)
  }

  const urls = linkText.split('\n').map((l) => l.trim()).filter(Boolean)
  const canSubmit = (files.length > 0 || urls.length > 0) && !loading

  const handleSubmit = async () => {
    setLoading(true)
    setError('')
    setResults(null)
    try {
      const collected = []
      if (files.length > 0) {
        const { data } = await sanitizeFiles(files)
        collected.push(...data.results)
      }
      if (urls.length > 0) {
        const { data } = await sanitizeLinks(urls)
        collected.push(...data.results)
      }
      setResults(collected)
    } catch (err) {
      setError(err.message || 'Sanitize failed')
    } finally {
      setLoading(false)
    }
  }

  const clearAll = () => {
    setFiles([])
    setLinkText('')
    setResults(null)
    setError('')
  }

  return (
    <div>
      <PageHeader
        title="Sanitize"
        description="Screen files and links for threats before you trust them."
      />

      <div className="grid grid-cols-1 lg:grid-cols-[minmax(340px,420px)_1fr] gap-6 items-start">
        <div className="space-y-6 min-w-0">
          <Card>
            <CardHeader title="Files" icon={Upload} description="Up to 20 files, 25 MB each. Nothing is stored." />
            <div className="px-5 pb-5 space-y-3">
              <div
                onDragOver={(e) => { e.preventDefault(); setDragging(true) }}
                onDragLeave={() => setDragging(false)}
                onDrop={onDrop}
                onClick={() => inputRef.current?.click()}
                role="button"
                tabIndex={0}
                onKeyDown={(e) => (e.key === 'Enter' || e.key === ' ') && inputRef.current?.click()}
                className={cx(
                  'rounded-card border border-dashed flex flex-col items-center justify-center text-center px-4 py-8 cursor-pointer transition-colors duration-150',
                  dragging ? 'border-accent bg-accent-soft/40' : 'border-line-strong hover:bg-hover'
                )}
              >
                <Upload className="w-5 h-5 text-ink-subtle mb-2" aria-hidden="true" />
                <p className="text-[13px] text-ink">Drop files here or click to browse</p>
                <input
                  ref={inputRef}
                  type="file"
                  multiple
                  className="sr-only"
                  onChange={(e) => { addFiles(e.target.files); e.target.value = '' }}
                />
              </div>

              {files.length > 0 && (
                <ul className="rounded-ctl border border-line divide-y divide-line overflow-hidden">
                  {files.map((file, i) => (
                    <li key={i} className="flex items-center justify-between gap-2 px-3 py-2">
                      <span className="min-w-0 flex items-center gap-2">
                        <FileText className="w-4 h-4 text-ink-subtle flex-shrink-0" aria-hidden="true" />
                        <span className="text-[13px] truncate">{file.name}</span>
                        <span className="text-xs text-ink-subtle tabular flex-shrink-0">{formatBytes(file.size)}</span>
                      </span>
                      <IconButton size="sm" icon={X} label={`Remove ${file.name}`} onClick={() => removeFile(i)} />
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </Card>

          <Card>
            <CardHeader title="Links" icon={Link2} description="One URL per line. URLs are not opened." />
            <div className="px-5 pb-5 space-y-2">
              <Label htmlFor="sanitize-links">URLs {urls.length > 0 && <span className="font-normal text-ink-subtle">{urls.length}</span>}</Label>
              <textarea
                id="sanitize-links"
                value={linkText}
                onChange={(e) => setLinkText(e.target.value)}
                placeholder={'https://example.com/download\nhttp://bit.ly/xyz'}
                rows={5}
                spellCheck={false}
                className="w-full rounded-ctl border border-line bg-surface text-ink text-[13px] font-mono p-3 placeholder:text-ink-subtle hover:border-line-strong focus:border-accent focus:outline-none focus-visible:outline-2 resize-y"
              />
            </div>
          </Card>

          {error && (
            <Callout tone="crit" icon={AlertTriangle} role="alert" title="Sanitize failed">{error}</Callout>
          )}

          <div className="flex gap-2">
            <Button
              variant="primary"
              size="lg"
              icon={ShieldCheck}
              loading={loading}
              disabled={!canSubmit}
              onClick={handleSubmit}
              className="flex-1"
            >
              {loading ? 'Screening…' : 'Sanitize'}
            </Button>
            {(files.length > 0 || linkText || results) && (
              <Button size="lg" icon={Trash2} onClick={clearAll} disabled={loading}>Clear</Button>
            )}
          </div>
        </div>

        <div className="min-w-0 space-y-4">
          {results ? (
            results.length > 0 ? (
              results.map((item, i) => <ResultCard key={i} item={item} />)
            ) : (
              <Card><EmptyState icon={ShieldCheck} title="Nothing to report" className="py-16" /></Card>
            )
          ) : (
            <Card>
              <EmptyState icon={ShieldCheck} title="No results yet" className="py-20">
                Add files or links, then run Sanitize to see a per-item verdict.
              </EmptyState>
            </Card>
          )}
        </div>
      </div>
    </div>
  )
}
