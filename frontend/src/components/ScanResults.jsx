import { useState } from 'react'
import { AlertTriangle, Download, SearchX } from 'lucide-react'
import { exportScan } from '../api/client'
import VulnerabilityCard from './VulnerabilityCard'
import { Button, Callout, Card, EmptyState, ProgressBar, Segmented, StatStrip } from './ui'

const SEVERITY_OPTIONS = ['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
const LABEL = { ALL: 'All', CRITICAL: 'Critical', HIGH: 'High', MEDIUM: 'Medium', LOW: 'Low', INFO: 'Info' }

export default function ScanResults({ scan, vulnerabilities }) {
  const [severityFilter, setSeverityFilter] = useState('ALL')

  if (!scan) return null

  if (scan.status === 'pending' || scan.status === 'running') {
    return (
      <Card className="p-6">
        <div className="flex items-baseline justify-between gap-4 mb-3">
          <div>
            <p className="text-sm font-medium">
              {scan.status === 'pending' ? 'Queued' : 'Scanning'} <span className="font-mono">{scan.target}</span>
            </p>
            <p className="text-[13px] text-ink-muted mt-0.5">
              {scan.current_scanner ? `Running ${scan.current_scanner}` : 'This can take a few minutes.'}
            </p>
          </div>
          <span className="text-sm tabular text-ink-muted">{scan.progress || 0}%</span>
        </div>
        <ProgressBar value={scan.progress || 0} label={`Scan progress for ${scan.target}`} />
        {vulnerabilities?.length > 0 && (
          <p className="text-xs text-ink-subtle mt-3 tabular">{vulnerabilities.length} findings so far</p>
        )}
      </Card>
    )
  }

  if (scan.status === 'failed') {
    return (
      <Callout tone="crit" icon={AlertTriangle} title="Scan failed">
        {scan.error_message || 'The backend did not report a reason.'}
      </Callout>
    )
  }

  const all = vulnerabilities || []
  const counts = SEVERITY_OPTIONS.reduce((acc, s) => {
    acc[s] = s === 'ALL' ? all.length : all.filter((v) => v.severity === s).length
    return acc
  }, {})
  const filteredVulns = severityFilter === 'ALL' ? all : all.filter((v) => v.severity === severityFilter)

  const handleExport = async (format) => {
    let url = null
    try {
      const response = await exportScan(scan.id, format)
      url = window.URL.createObjectURL(new Blob([response.data]))
      const link = document.createElement('a')
      link.href = url
      link.download = `scan_${scan.id}.${format}`
      link.click()
    } catch (err) { console.error('Export failed:', err) }
    finally { if (url) window.URL.revokeObjectURL(url) }
  }

  return (
    <div className="space-y-5">
      <StatStrip
        items={[
          { label: 'Findings', value: scan.total_vulnerabilities },
          { label: 'Critical', value: scan.critical_count, tone: scan.critical_count ? 'crit' : undefined },
          { label: 'High', value: scan.high_count, tone: scan.high_count ? 'high' : undefined },
          { label: 'Medium', value: scan.medium_count, tone: scan.medium_count ? 'med' : undefined },
          { label: 'Mean CVSS', value: Number(scan.avg_cvss || 0).toFixed(1) },
        ]}
      />

      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <Segmented
          label="Filter by severity"
          size="sm"
          value={severityFilter}
          onChange={setSeverityFilter}
          options={SEVERITY_OPTIONS.filter((s) => s === 'ALL' || counts[s] > 0).map((s) => ({
            value: s, label: LABEL[s], count: counts[s],
          }))}
        />
        <div className="flex gap-2 flex-shrink-0">
          <Button size="sm" icon={Download} onClick={() => handleExport('json')}>JSON</Button>
          <Button size="sm" icon={Download} onClick={() => handleExport('csv')}>CSV</Button>
        </div>
      </div>

      <Card className="overflow-hidden">
        {filteredVulns.length > 0 ? (
          <ul className="divide-y divide-line">
            {filteredVulns.map((vuln) => (
              <li key={vuln.id}><VulnerabilityCard vuln={vuln} /></li>
            ))}
          </ul>
        ) : (
          <EmptyState icon={SearchX} title={severityFilter === 'ALL' ? 'No findings' : `No ${LABEL[severityFilter].toLowerCase()} findings`}>
            {severityFilter === 'ALL' ? 'The selected scanners reported nothing for this target.' : 'Try another severity filter.'}
          </EmptyState>
        )}
      </Card>
    </div>
  )
}
