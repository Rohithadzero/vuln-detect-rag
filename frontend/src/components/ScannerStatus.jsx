import { Badge } from './ui'

export const SCANNER_LABELS = {
  nmap: 'Nmap',
  nuclei: 'Nuclei',
  openvas: 'OpenVAS',
  zap: 'OWASP ZAP',
  nikto: 'Nikto',
  tlsscan: 'testssl / sslyze',
  whatweb: 'WhatWeb',
  trivy: 'Trivy',
  osv: 'OSV-Scanner',
  grype: 'Grype',
  nessus: 'Nessus',
  burp: 'Burp Suite',
}

// Reports exactly what /api/health says. A scanner the backend cannot run is
// "Not installed", never "Mock mode" or "Ready".
export default function ScannerStatus({ health }) {
  if (!health) {
    return <p className="px-5 pb-4 text-[13px] text-ink-muted">Backend unreachable.</p>
  }
  const entries = Object.entries(health.scanners || {})
  const ready = entries.filter(([, ok]) => ok).length

  return (
    <div className="px-5 pb-4">
      <p className="text-xs text-ink-muted mb-2">
        <span className="tabular">{ready}</span> of <span className="tabular">{entries.length}</span> available on this machine
      </p>
      <ul className="divide-y divide-line">
        {entries.map(([name, ok]) => (
          <li key={name} className="flex items-center justify-between py-2 text-[13px]">
            <span className={ok ? 'text-ink' : 'text-ink-muted'}>{SCANNER_LABELS[name] || name}</span>
            {ok ? <Badge tone="ok">Ready</Badge> : <Badge>Not installed</Badge>}
          </li>
        ))}
      </ul>
    </div>
  )
}
