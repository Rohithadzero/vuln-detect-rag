import { useState } from 'react'
import { AlertTriangle, Shield, Download, Filter } from 'lucide-react'
import { exportScan } from '../api/client'
import VulnerabilityCard from './VulnerabilityCard'

const SEVERITY_OPTIONS = ['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']

export default function ScanResults({ scan, vulnerabilities }) {
  const [severityFilter, setSeverityFilter] = useState('ALL')

  if (!scan) return null

  if (scan.status === 'pending' || scan.status === 'running') {
    return (
      <div className="flex flex-col items-center justify-center py-12">
        <div className="w-8 h-8 border-4 border-black border-t-neo-cyan bg-white animate-spin mb-4" />
        <p className="text-lg font-black uppercase">Scanning {scan.target}...</p>
        <p className="text-sm mt-1 font-bold text-gray-600">
          {scan.current_scanner ? `Running ${scan.current_scanner}...` : 'This may take a few minutes'}
        </p>
        <div className="w-64 mt-4 bg-white border-3 border-black p-3 shadow-[4px_4px_0px_0px_#000]">
          <div className="flex justify-between text-[10px] font-black uppercase mb-1">
            <span>Progress</span>
            <span>{scan.progress || 0}%</span>
          </div>
          <div className="h-3 bg-gray-200 border-2 border-black overflow-hidden">
            <div className="h-full bg-neo-cyan transition-all duration-500" style={{ width: `${scan.progress || 0}%` }} />
          </div>
        </div>
      </div>
    )
  }

  if (scan.status === 'failed') {
    return (
      <div className="flex flex-col items-center justify-center py-12 text-neo-red px-4">
        <AlertTriangle className="w-8 h-8 mb-4" />
        <p className="text-lg font-black uppercase">Scan Failed</p>
        <p className="text-sm mt-1 font-bold text-gray-600 max-w-lg break-words">{scan.error_message}</p>
      </div>
    )
  }

  const filteredVulns = severityFilter === 'ALL'
    ? (vulnerabilities || [])
    : (vulnerabilities || []).filter(v => v.severity === severityFilter)

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
    <div className="space-y-6">
      {/* Summary Stats */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3">
        {[
          { label: 'Total', value: scan.total_vulnerabilities, color: 'bg-white' },
          { label: 'Critical', value: scan.critical_count, color: 'bg-severity-critical' },
          { label: 'High', value: scan.high_count, color: 'bg-severity-high' },
          { label: 'Medium', value: scan.medium_count, color: 'bg-severity-medium' },
          { label: 'Avg CVSS', value: scan.avg_cvss, color: 'bg-white' },
        ].map((s, i) => (
          <div key={i} className={`border-3 border-black p-3 shadow-[4px_4px_0px_0px_#000] ${s.color}`}>
            <div className="text-[10px] font-black uppercase tracking-wider">{s.label}</div>
            <div className="text-xl sm:text-2xl font-black mt-1">{s.value}</div>
          </div>
        ))}
      </div>

      {/* Toolbar */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
        <div className="flex flex-wrap items-center gap-2">
          <Filter className="w-4 h-4 flex-shrink-0" />
          {SEVERITY_OPTIONS.map((s) => (
            <button
              key={s}
              onClick={() => setSeverityFilter(s)}
              className={`px-2.5 py-1.5 text-[10px] font-black uppercase border-2 border-black transition-all ${
                severityFilter === s
                  ? 'bg-neo-cyan shadow-[2px_2px_0px_0px_#000]'
                  : 'bg-white hover:bg-gray-100'
              }`}
            >
              {s}
            </button>
          ))}
        </div>
        <div className="flex gap-2 flex-shrink-0">
          <button onClick={() => handleExport('json')} className="px-3 py-1.5 bg-white border-3 border-black text-[10px] font-black uppercase nb-btn flex items-center gap-1.5">
            <Download className="w-3 h-3" /> JSON
          </button>
          <button onClick={() => handleExport('csv')} className="px-3 py-1.5 bg-white border-3 border-black text-[10px] font-black uppercase nb-btn flex items-center gap-1.5">
            <Download className="w-3 h-3" /> CSV
          </button>
        </div>
      </div>

      {/* Vulnerability List */}
      <div className="space-y-3">
        <h3 className="text-lg font-black uppercase flex items-center gap-2">
          <Shield className="w-5 h-5" />
          Vulnerabilities ({filteredVulns.length})
        </h3>
        {filteredVulns.map((vuln) => (
          <VulnerabilityCard key={vuln.id} vuln={vuln} />
        ))}
        {filteredVulns.length === 0 && (
          <div className="text-center py-8 text-gray-400 text-sm font-bold uppercase">
            No {severityFilter !== 'ALL' ? severityFilter.toLowerCase() : ''} vulnerabilities found
          </div>
        )}
      </div>
    </div>
  )
}
