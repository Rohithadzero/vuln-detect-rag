import { useState } from 'react'
import { Play, Star, AlertTriangle, Check } from 'lucide-react'
import { normalizeTarget } from '../utils/target'
import { Badge, Button, Callout, IconButton, Input, Label, cx } from './ui'

// `status` tells the user, before starting a scan, whether a tool can run for
// real. Presenting a simulated scanner as live is the single most misleading
// thing this UI could do.
const scanners = [
  { id: 'nmap', label: 'Nmap', desc: 'Ports and service detection', status: 'live', group: 'Network' },
  { id: 'nuclei', label: 'Nuclei', desc: 'Template-based vulnerability checks', status: 'live', group: 'Network' },
  { id: 'openvas', label: 'OpenVAS', desc: 'Full vulnerability assessment', status: 'live', group: 'Network', note: 'Needs a running GVM stack' },
  { id: 'zap', label: 'OWASP ZAP', desc: 'Dynamic application testing', status: 'live', group: 'Web' },
  { id: 'nikto', label: 'Nikto', desc: 'Server misconfiguration, outdated software', status: 'live', group: 'Web' },
  { id: 'tlsscan', label: 'testssl / sslyze', desc: 'TLS protocols, ciphers, certificates', status: 'live', group: 'Web' },
  { id: 'whatweb', label: 'WhatWeb', desc: 'Technology fingerprinting', status: 'live', group: 'Web' },
  { id: 'trivy', label: 'Trivy', desc: 'Containers, dependencies, IaC, secrets', status: 'live', group: 'Supply chain', note: 'Scans a path or image, not a hostname' },
  { id: 'osv', label: 'OSV-Scanner', desc: 'Dependency manifests against OSV', status: 'live', group: 'Supply chain', note: 'Scans a project directory' },
  { id: 'grype', label: 'Grype', desc: 'Image and filesystem CVE matching', status: 'live', group: 'Supply chain', note: 'Scans a path or image' },
  { id: 'burp', label: 'Burp Suite', desc: 'Web application testing', status: 'licence', group: 'Commercial', note: 'Needs a Burp Pro licence' },
  { id: 'nessus', label: 'Nessus', desc: 'Enterprise vulnerability scanner', status: 'simulated', group: 'Commercial', note: 'Returns simulated sample data' },
]

const GROUPS = ['Network', 'Web', 'Supply chain', 'Commercial']
const defaultScanners = ['nmap', 'nuclei']

export default function ScanForm({ onStartScan, loading, onAddFavorite, error, availability }) {
  const [target, setTarget] = useState('')
  const [selected, setSelected] = useState(defaultScanners)
  const [showAll, setShowAll] = useState(false)

  const toggleScanner = (id) => {
    setSelected((prev) => (prev.includes(id) ? prev.filter((s) => s !== id) : [...prev, id]))
  }

  const handleSubmit = (e) => {
    e.preventDefault()
    const clean = normalizeTarget(target)
    if (!clean || selected.length === 0) return
    onStartScan(clean, selected)
  }

  const needsWarning = selected.some((id) => scanners.find((s) => s.id === id)?.status !== 'live')

  // Tools the backend reports as missing are tucked away so the ones that can
  // run, and the Start button, stay in view. Selected tools always show.
  const isVisible = (s) => showAll || !availability || availability[s.id] || selected.includes(s.id)
  const hiddenCount = scanners.filter((s) => !isVisible(s)).length

  return (
    <form onSubmit={handleSubmit} className="space-y-5">
      <div>
        <Label htmlFor="scan-target" hint="domain or public IP">Target</Label>
        <div className="flex gap-2">
          <Input
            id="scan-target"
            className="flex-1 min-w-0"
            inputClassName="font-mono"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder="scanme.nmap.org"
            disabled={loading}
            autoComplete="off"
            spellCheck={false}
          />
          {target.trim() && onAddFavorite && (
            <IconButton
              icon={Star}
              label="Save target"
              className="border border-line"
              onClick={() => onAddFavorite(normalizeTarget(target))}
            />
          )}
        </div>
      </div>

      <fieldset>
        <legend className="text-[13px] font-medium mb-2">
          Scanners <span className="font-normal text-ink-subtle tabular">{selected.length} selected</span>
        </legend>
        <div className="space-y-4">
          {GROUPS.filter((group) => scanners.some((s) => s.group === group && isVisible(s))).map((group) => (
            <div key={group}>
              <p className="text-xs text-ink-subtle mb-1">{group}</p>
              <div className="rounded-ctl border border-line divide-y divide-line overflow-hidden">
                {scanners.filter((s) => s.group === group && isVisible(s)).map((s) => {
                  const on = selected.includes(s.id)
                  const installed = availability ? availability[s.id] : undefined
                  return (
                    <label
                      key={s.id}
                      className={cx(
                        'flex items-start gap-3 px-3 py-2.5 cursor-pointer transition-colors duration-150',
                        on ? 'bg-accent-soft/40' : 'hover:bg-hover'
                      )}
                    >
                      <input type="checkbox" checked={on} onChange={() => toggleScanner(s.id)} className="peer sr-only" />
                      <span
                        className={cx(
                          'mt-0.5 w-4 h-4 rounded-[5px] border flex items-center justify-center flex-shrink-0 transition-colors',
                          'peer-focus-visible:outline peer-focus-visible:outline-2 peer-focus-visible:outline-accent peer-focus-visible:outline-offset-2',
                          on ? 'bg-accent border-accent text-accent-fg' : 'border-line-strong bg-surface'
                        )}
                        aria-hidden="true"
                      >
                        {on && <Check className="w-3 h-3" strokeWidth={3} />}
                      </span>
                      <span className="min-w-0 flex-1">
                        <span className="flex items-center gap-1.5 flex-wrap">
                          <span className="text-[13px] font-medium">{s.label}</span>
                          {s.status === 'licence' && <Badge tone="med">Paid licence</Badge>}
                          {s.status === 'simulated' && <Badge tone="high">Simulated</Badge>}
                          {s.status === 'live' && installed === false && <Badge>Not installed</Badge>}
                        </span>
                        <span className="block text-xs text-ink-muted">{s.desc}</span>
                        {s.note && <span className="block text-xs text-ink-subtle">{s.note}</span>}
                      </span>
                    </label>
                  )
                })}
              </div>
            </div>
          ))}
        </div>

        {(hiddenCount > 0 || showAll) && availability && (
          <button
            type="button"
            onClick={() => setShowAll(!showAll)}
            aria-expanded={showAll}
            className="mt-2 text-[13px] text-accent-text hover:underline"
          >
            {showAll ? 'Hide unavailable scanners' : `Show ${hiddenCount} unavailable scanners`}
          </button>
        )}

        {needsWarning && (
          <Callout tone="warn" icon={AlertTriangle} className="mt-3">
            Some selected tools cannot run live here and return simulated sample data. Those findings are
            labelled Simulated and do not describe the real target.
          </Callout>
        )}
      </fieldset>

      {error && (
        <Callout tone="crit" icon={AlertTriangle} role="alert" title="Scan not started">
          {error}
        </Callout>
      )}

      <Button
        type="submit"
        variant="primary"
        size="lg"
        icon={Play}
        loading={loading}
        disabled={!target.trim() || selected.length === 0}
        className="w-full"
      >
        {loading ? 'Scanning…' : 'Start scan'}
      </Button>
    </form>
  )
}
