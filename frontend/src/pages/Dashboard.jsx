import { useState, useEffect, useMemo } from 'react'
import { useNavigate } from 'react-router-dom'
import { AlertTriangle, ChevronRight, Globe, Radar, Server } from 'lucide-react'
import { getStats, getHealth, startScan } from '../api/client'
import { normalizeTarget } from '../utils/target'
import Skeleton, { SkeletonRegion, SkeletonStatCards, SkeletonPanel } from '../components/Skeleton'
import ScannerStatus from '../components/ScannerStatus'
import {
  Button, Card, CardHeader, Input, PageHeader, StatStrip, StatusBadge, EmptyState, Callout, cx,
} from '../components/ui'

const SEVERITIES = [
  { key: 'critical_vulns', label: 'Critical', bar: 'bg-crit-solid', text: 'text-crit' },
  { key: 'high_vulns', label: 'High', bar: 'bg-high-solid', text: 'text-high' },
  { key: 'medium_vulns', label: 'Medium', bar: 'bg-med-solid', text: 'text-med' },
  { key: 'low_vulns', label: 'Low', bar: 'bg-low-solid', text: 'text-low' },
]

function timeAgo(iso) {
  if (!iso) return ''
  const s = Math.round((Date.now() - new Date(iso + (iso.endsWith('Z') ? '' : 'Z')).getTime()) / 1000)
  if (s < 60) return 'just now'
  const m = Math.round(s / 60)
  if (m < 60) return `${m} min ago`
  const h = Math.round(m / 60)
  if (h < 24) return `${h} h ago`
  return new Date(iso).toLocaleDateString()
}

export default function Dashboard() {
  const [stats, setStats] = useState(null)
  const [health, setHealth] = useState(undefined)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [targetUrl, setTargetUrl] = useState('')
  const [isScanning, setIsScanning] = useState(false)
  const [scanError, setScanError] = useState('')
  const navigate = useNavigate()

  useEffect(() => {
    loadStats()
    loadHealth()
    const interval = setInterval(() => { loadStats(); loadHealth() }, 30000)
    return () => clearInterval(interval)
  }, [])

  const loadHealth = async () => {
    try {
      const { data } = await getHealth()
      setHealth(data)
    } catch {
      setHealth(null)
    }
  }

  const loadStats = async () => {
    try {
      const { data } = await getStats()
      setStats(data)
      setError(null)
    } catch (err) {
      setError(err.message || 'Failed to load dashboard data')
    } finally {
      setLoading(false)
    }
  }

  const handleStartScan = async (e) => {
    e.preventDefault()
    if (!targetUrl.trim()) return
    setIsScanning(true)
    setScanError('')
    try {
      const { data } = await startScan(normalizeTarget(targetUrl), ['nmap', 'nuclei'])
      setTargetUrl('')
      navigate(`/scans?scan=${data.id}`)
    } catch (err) {
      setScanError(err.message || 'Failed to start scan')
    } finally {
      setIsScanning(false)
    }
  }

  // Hooks stay above the early returns: calling useMemo after them changed the
  // hook count once stats arrived and blanked the dashboard (v4.5 fix).
  const breakdown = useMemo(() => {
    const total = SEVERITIES.reduce((sum, s) => sum + (stats?.[s.key] || 0), 0)
    return {
      total,
      rows: SEVERITIES.map((s) => ({ ...s, value: stats?.[s.key] || 0, pct: total ? ((stats?.[s.key] || 0) / total) * 100 : 0 })),
    }
  }, [stats])

  if (loading) {
    return (
      <SkeletonRegion label="Loading dashboard" className="space-y-6">
        <div className="space-y-2">
          <Skeleton className="h-7 w-48" />
          <Skeleton className="h-3 w-72" />
        </div>
        <Skeleton className="h-[72px] w-full rounded-card" />
        <SkeletonStatCards count={4} />
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <SkeletonPanel className="lg:col-span-2" />
          <SkeletonPanel />
        </div>
      </SkeletonRegion>
    )
  }

  if (error && !stats) {
    return (
      <EmptyState
        icon={AlertTriangle}
        title="Could not load the dashboard"
        className="flex-1"
        action={<Button variant="primary" onClick={loadStats}>Retry</Button>}
      >
        {error}
      </EmptyState>
    )
  }

  return (
    <div className="space-y-6">
      <PageHeader title="Dashboard" description="Findings across every scan run on this machine." />

      <Card>
        <form onSubmit={handleStartScan} className="p-4 flex flex-col sm:flex-row gap-3 sm:items-center">
          <label htmlFor="quick-target" className="text-[13px] font-medium sm:w-28 flex-shrink-0">
            Quick scan
            <span className="block text-xs font-normal text-ink-subtle">Nmap + Nuclei</span>
          </label>
          <Input
            id="quick-target"
            icon={Globe}
            className="flex-1"
            inputClassName="font-mono"
            value={targetUrl}
            onChange={(e) => setTargetUrl(e.target.value)}
            placeholder="scanme.nmap.org"
            disabled={isScanning}
            autoComplete="off"
            spellCheck={false}
          />
          <Button type="submit" variant="primary" icon={Radar} loading={isScanning} disabled={!targetUrl.trim()}>
            Start scan
          </Button>
        </form>
        {scanError && (
          <div className="px-4 pb-4">
            <Callout tone="crit" icon={AlertTriangle} role="alert">{scanError}</Callout>
          </div>
        )}
      </Card>

      <StatStrip
        items={[
          { label: 'Scans', value: stats?.total_scans ?? 0 },
          { label: 'Findings', value: stats?.total_vulnerabilities ?? 0 },
          { label: 'Critical', value: stats?.critical_vulns ?? 0, tone: stats?.critical_vulns ? 'crit' : undefined },
          { label: 'Mean CVSS', value: (stats?.avg_cvss ?? 0).toFixed(1) },
        ]}
      />

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 items-start">
        <div className="lg:col-span-2 space-y-6 min-w-0">
        <Card>
          <CardHeader title="Severity breakdown" description={breakdown.total ? `${breakdown.total} findings with a severity rating` : undefined} />
          {breakdown.total > 0 ? (
            <div className="px-5 pb-5 space-y-5">
              <div className="flex h-2.5 rounded-full overflow-hidden bg-hover" aria-hidden="true">
                {breakdown.rows.map((r) => r.value > 0 && (
                  <div key={r.key} className={r.bar} style={{ width: `${r.pct}%` }} />
                ))}
              </div>
              <ul className="space-y-3">
                {breakdown.rows.map((r) => (
                  <li key={r.key} className="grid grid-cols-[80px_1fr_auto] items-center gap-3 text-[13px]">
                    <span className="flex items-center gap-2">
                      <span className={cx('w-2 h-2 rounded-full', r.bar)} aria-hidden="true" />
                      {r.label}
                    </span>
                    <div className="h-1.5 rounded-full bg-hover overflow-hidden" aria-hidden="true">
                      <div className={cx('h-full rounded-full', r.bar)} style={{ width: `${r.pct}%` }} />
                    </div>
                    <span className="tabular text-right w-24">
                      <span className="font-medium">{r.value}</span>
                      <span className="text-ink-subtle"> · {r.pct.toFixed(0)}%</span>
                    </span>
                  </li>
                ))}
              </ul>
            </div>
          ) : (
            <EmptyState title="No findings yet">Run a scan to see how its findings break down by severity.</EmptyState>
          )}
        </Card>


      <Card>
        <CardHeader
          title="Recent scans"
          actions={<Button size="sm" variant="ghost" onClick={() => navigate('/scans')}>View all</Button>}
        />
        {stats?.recent_scans?.length > 0 ? (
          <ul className="border-t border-line divide-y divide-line">
            {stats.recent_scans.map((scan) => (
              <li key={scan.id}>
                <button
                  className="w-full px-5 py-3 flex items-center gap-4 text-left hover:bg-hover transition-colors duration-150"
                  onClick={() => navigate(`/scans?scan=${scan.id}`)}
                >
                  <span className="font-mono text-[13px] truncate flex-1 min-w-0">{scan.target}</span>
                  <StatusBadge status={scan.status} />
                  <span className="text-[13px] text-ink-muted tabular w-24 text-right hidden sm:block">
                    {scan.total_vulnerabilities} findings
                  </span>
                  <span className="text-xs text-ink-subtle w-20 text-right hidden md:block">{timeAgo(scan.started_at)}</span>
                  <ChevronRight className="w-4 h-4 text-ink-subtle flex-shrink-0" aria-hidden="true" />
                </button>
              </li>
            ))}
          </ul>
        ) : (
          <EmptyState icon={Radar} title="No scans yet">Enter a target above to run your first scan.</EmptyState>
        )}
      </Card>
        </div>

        <Card>
          <CardHeader title="Scanners" icon={Server} />
          {health === undefined ? (
            <div className="px-5 pb-5 space-y-3"><Skeleton className="h-3 w-full" /><Skeleton className="h-3 w-4/5" /></div>
          ) : (
            <ScannerStatus health={health} />
          )}
        </Card>
      </div>
    </div>
  )
}
