import { useState, useEffect, useMemo } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, Legend
} from 'recharts'
import {
  Shield, AlertTriangle, TrendingUp, Activity, ChevronRight
} from 'lucide-react'
import { getStats, getHealth, startScan } from '../api/client'
import Skeleton, { SkeletonRegion, SkeletonStatCards, SkeletonPanel } from '../components/Skeleton'

const SEVERITY_COLORS = {
  CRITICAL: '#ef4444',
  HIGH: '#ea580c',
  MEDIUM: '#ca8a04',
  LOW: '#2563eb',
}

const statusColors = {
  completed: 'bg-neo-green text-black',
  running: 'bg-neo-cyan text-black',
  pending: 'bg-neo-yellow text-black',
  failed: 'bg-neo-red text-white',
}

export default function Dashboard() {
  const [stats, setStats] = useState(null)
  const [health, setHealth] = useState(null)
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
    } catch (err) {
      console.error('Failed to load health:', err)
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
      const { data } = await startScan(targetUrl, ['nmap', 'nuclei'])
      setTargetUrl('')
      navigate(`/scans?scan=${data.id}`)
    } catch (err) {
      setScanError(err.message || 'Failed to start scan')
    } finally {
      setIsScanning(false)
    }
  }

  // Must stay above the early returns below. Hooks have to run in the same
  // order on every render, and the loading/error branches return before this
  // point on the first pass -- calling useMemo after them changes the hook
  // count as soon as stats arrive, and React aborts the render with
  // "rendered more hooks than during the previous render". That crash is why
  // the dashboard went blank the moment its data loaded.
  const severityData = useMemo(() => [
    { name: 'Critical', value: stats?.critical_vulns || 0, color: SEVERITY_COLORS.CRITICAL },
    { name: 'High', value: stats?.high_vulns || 0, color: SEVERITY_COLORS.HIGH },
    { name: 'Medium', value: stats?.medium_vulns || 0, color: SEVERITY_COLORS.MEDIUM },
    { name: 'Low', value: stats?.low_vulns || 0, color: SEVERITY_COLORS.LOW },
  ].filter(d => d.value > 0), [stats?.critical_vulns, stats?.high_vulns, stats?.medium_vulns, stats?.low_vulns])

  if (loading) {
    // Mirrors the real layout below -- header, scan form, four stat tiles,
    // three panels -- so nothing shifts position when the data lands.
    return (
      <SkeletonRegion label="Loading dashboard" className="space-y-6 min-w-0">
        <div className="flex flex-col gap-4">
          <div className="space-y-2">
            <Skeleton className="h-8 w-56" />
            <Skeleton className="h-3 w-72" />
          </div>
          <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-2">
            <Skeleton bordered className="h-[50px] flex-1 min-w-0" />
            <Skeleton bordered className="h-[50px] w-full sm:w-32 flex-shrink-0" />
          </div>
        </div>
        <SkeletonStatCards count={4} />
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <SkeletonPanel />
          <SkeletonPanel />
          <SkeletonPanel />
        </div>
      </SkeletonRegion>
    )
  }

  if (error && !stats) {
    return (
      <div className="flex flex-col items-center justify-center h-full">
        <AlertTriangle className="w-12 h-12 text-neo-red mb-3" />
        <p className="text-xl font-black mb-1 uppercase">Failed to load</p>
        <p className="text-sm mb-4 font-bold text-gray-600">{error}</p>
        <button onClick={loadStats} className="px-6 py-3 bg-neo-yellow nb-btn text-sm">Retry</button>
      </div>
    )
  }

  return (
    <div className="space-y-6 min-w-0">
      <div className="flex flex-col gap-4">
        <div>
          <h1 className="text-3xl font-black uppercase tracking-tight">Dashboard</h1>
          <p className="text-sm font-bold text-gray-600 mt-1 uppercase tracking-wider">Vulnerability scanning overview</p>
        </div>

        <form onSubmit={handleStartScan} className="flex flex-col sm:flex-row items-stretch sm:items-center gap-2">
          <div className="flex items-center gap-2 flex-1 min-w-0 bg-white border-3 border-black px-4 py-3 nb-input">
            <Shield className="w-5 h-5 text-gray-400 flex-shrink-0" />
            <input
              type="text"
              value={targetUrl}
              onChange={(e) => setTargetUrl(e.target.value)}
              placeholder="Enter target (e.g., example.com)"
              className="bg-transparent border-none outline-none text-black text-sm w-full placeholder-gray-400 font-mono"
              disabled={isScanning}
              required
            />
          </div>
          <button
            type="submit"
            disabled={isScanning || !targetUrl.trim()}
            className="px-6 py-3 bg-neo-red text-white nb-btn disabled:bg-gray-300 disabled:text-gray-500 disabled:shadow-none flex items-center justify-center gap-2 flex-shrink-0 text-sm"
          >
            {isScanning ? (
              <div className="w-4 h-4 border-2 border-white/30 border-t-white animate-spin" />
            ) : 'Start Scan'}
          </button>
        </form>
        {scanError && <div className="text-neo-red text-xs font-bold">{scanError}</div>}
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {[
          { label: 'Total Scans', value: stats?.total_scans || 0, icon: Activity, color: 'bg-neo-cyan' },
          { label: 'Vulnerabilities', value: stats?.total_vulnerabilities || 0, icon: AlertTriangle, color: 'bg-neo-orange' },
          { label: 'Critical Vulns', value: stats?.critical_vulns || 0, icon: Shield, color: 'bg-neo-red' },
          { label: 'Avg CVSS', value: stats?.avg_cvss || 0, icon: TrendingUp, color: 'bg-neo-green' },
        ].map((card, i) => (
          <div key={i} className={`${card.color} border-3 border-black p-5 shadow-neb-sm hover:shadow-neb-hover hover:translate-x-[-2px] hover:translate-y-[-2px] transition-all`}>
            <div className="flex items-center gap-3">
              <card.icon className="w-6 h-6" />
              <div>
                <div className="text-2xl font-black">{card.value}</div>
                <div className="text-[10px] font-bold uppercase tracking-wider opacity-70">{card.label}</div>
              </div>
            </div>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Severity Distribution */}
        <div className="bg-white border-3 border-black p-5 shadow-neb">
          <h3 className="text-sm font-black uppercase tracking-wider mb-4">Severity Distribution</h3>
          {severityData.length > 0 ? (
            <ResponsiveContainer width="100%" height={200}>
              <PieChart>
                <Pie data={severityData} cx="50%" cy="50%" innerRadius={55} outerRadius={80} dataKey="value" stroke="#000" strokeWidth={2}>
                  {severityData.map((entry, index) => (
                    <Cell key={index} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip contentStyle={{ backgroundColor: '#fff', border: '3px solid #000', borderRadius: 0, color: '#000', fontWeight: 700 }} />
                <Legend verticalAlign="bottom" height={36} wrapperStyle={{ fontWeight: 700, fontSize: '12px' }} />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <div className="flex items-center justify-center h-[200px] text-gray-400 text-sm font-bold">No data yet</div>
          )}
        </div>

        {/* Severity Bar Chart */}
        <div className="bg-white border-3 border-black p-5 shadow-neb">
          <h3 className="text-sm font-black uppercase tracking-wider mb-4">Vulnerability Count</h3>
          {severityData.length > 0 ? (
            <ResponsiveContainer width="100%" height={200}>
              <BarChart data={severityData}>
                <XAxis dataKey="name" tick={{ fill: '#000', fontSize: 11, fontWeight: 700 }} axisLine={{ stroke: '#000', strokeWidth: 2 }} tickLine={false} />
                <YAxis tick={{ fill: '#000', fontSize: 11, fontWeight: 700 }} axisLine={{ stroke: '#000', strokeWidth: 2 }} tickLine={false} />
                <Tooltip contentStyle={{ backgroundColor: '#fff', border: '3px solid #000', borderRadius: 0, color: '#000', fontWeight: 700 }} />
                <Bar dataKey="value" radius={0} stroke="#000" strokeWidth={2}>
                  {severityData.map((entry, index) => (
                    <Cell key={index} fill={entry.color} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <div className="flex items-center justify-center h-[200px] text-gray-400 text-sm font-bold">No data yet</div>
          )}
        </div>

        {/* System Health */}
        <div className="bg-white border-3 border-black p-5 shadow-neb">
          <h3 className="text-sm font-black uppercase tracking-wider mb-4">System Health</h3>
          <div className="space-y-3">
            {[
              { label: 'Backend API', status: health ? 'Online' : 'Offline', ok: !!health },
              { label: 'Nmap', status: health?.scanners?.nmap ? 'Ready' : 'Mock Mode', ok: health?.scanners?.nmap },
              { label: 'Nuclei', status: health?.scanners?.nuclei ? 'Ready' : 'Mock Mode', ok: health?.scanners?.nuclei },
              { label: 'OpenVAS', status: health?.scanners?.openvas ? 'Ready' : 'Mock Mode', ok: health?.scanners?.openvas },
              { label: 'Nessus', status: health?.scanners?.nessus ? 'Ready' : 'Mock Mode', ok: health?.scanners?.nessus },
              { label: 'Burp Suite', status: health?.scanners?.burp ? 'Ready' : 'Mock Mode', ok: health?.scanners?.burp },
              { label: 'OWASP ZAP', status: health?.scanners?.zap ? 'Ready' : 'Mock Mode', ok: health?.scanners?.zap },
            ].map((item, i) => (
              <div key={i} className="flex items-center justify-between">
                <span className="text-xs font-bold uppercase">{item.label}</span>
                <span className={`px-2 py-0.5 text-[10px] font-black uppercase border-2 border-black ${item.ok ? 'bg-neo-green' : 'bg-gray-200'}`}>
                  {item.status}
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Recent Scans */}
      <div className="bg-white border-3 border-black shadow-neb overflow-hidden">
        <div className="p-4 border-b-[3px] border-black bg-neo-yellow">
          <h3 className="text-sm font-black uppercase tracking-wider">Recent Scans</h3>
        </div>
        <div className="divide-y-[3px] divide-black">
          {stats?.recent_scans?.length > 0 ? (
            stats.recent_scans.map((scan) => (
              <button
                key={scan.id}
                className="px-5 py-3 flex flex-col sm:flex-row sm:items-center justify-between gap-2 hover:bg-gray-50 cursor-pointer transition-colors w-full text-left"
                onClick={() => navigate(`/scans?scan=${scan.id}`)}
                aria-label={`View scan for ${scan.target}`}
              >
                <div className="flex items-center gap-3 min-w-0">
                  <span className="text-sm font-bold truncate font-mono">{scan.target}</span>
                  <span className={`px-2 py-0.5 text-[10px] font-black uppercase border-2 border-black flex-shrink-0 ${statusColors[scan.status]}`}>
                    {scan.status}
                  </span>
                </div>
                <div className="flex items-center gap-3 text-xs flex-shrink-0">
                  <span className="font-bold">{scan.total_vulnerabilities} vulns</span>
                  <span className="text-gray-500 hidden sm:inline font-mono text-[10px]">
                    {new Date(scan.started_at).toLocaleString()}
                  </span>
                  <ChevronRight className="w-4 h-4" />
                </div>
              </button>
            ))
          ) : (
            <div className="p-8 text-center text-gray-400 text-sm font-bold uppercase">
              No scans yet. Start a scan from the dashboard.
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
