import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { Search, Bug, ExternalLink } from 'lucide-react'
import { searchCVEs } from '../api/client'
import { SkeletonRegion, SkeletonRows } from '../components/Skeleton'

const severityColors = {
  CRITICAL: 'text-severity-critical',
  HIGH: 'text-severity-high',
  MEDIUM: 'text-severity-medium',
  LOW: 'text-severity-low',
}

const SEVERITIES = ['', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW']

export default function CVEBrowse() {
  const navigate = useNavigate()
  const [cves, setCves] = useState([])
  const [loading, setLoading] = useState(false)
  const [query, setQuery] = useState('')
  const [severity, setSeverity] = useState('')
  const [exploitOnly, setExploitOnly] = useState(false)

  useEffect(() => { searchCVE() }, [severity, exploitOnly])

  const searchCVE = async () => {
    setLoading(true)
    try {
      const { data } = await searchCVEs(query, severity, exploitOnly)
      setCves(data)
    } catch (err) { console.error(err) } finally { setLoading(false) }
  }

  const handleSearch = (e) => { e.preventDefault(); searchCVE() }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-black uppercase tracking-tight">CVE Database</h1>
        <p className="text-sm font-bold text-gray-600 mt-1 uppercase tracking-wider">Browse and search known vulnerabilities</p>
      </div>

      <div className="flex flex-col gap-3">
        <form onSubmit={handleSearch} className="flex gap-2">
          <input
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search CVE descriptions..."
            className="flex-1 min-w-0 bg-white border-3 border-black px-4 py-2.5 text-sm font-mono nb-input"
          />
          <button type="submit" className="px-4 py-2.5 bg-neo-yellow border-3 border-black nb-btn">
            <Search className="w-4 h-4" />
          </button>
        </form>

        <div className="flex flex-wrap gap-2">
          {SEVERITIES.map((s) => (
            <button
              key={s || 'all'}
              onClick={() => setSeverity(s)}
              className={`px-3 py-2 text-[10px] font-black uppercase border-3 border-black transition-all ${
                severity === s ? 'bg-neo-cyan shadow-neb-xs' : 'bg-white shadow-neb-sm hover:shadow-neb-xs'
              }`}
            >
              {s || 'ALL'}
            </button>
          ))}
          <button
            onClick={() => setExploitOnly(!exploitOnly)}
            className={`px-3 py-2 text-[10px] font-black uppercase border-3 border-black flex items-center gap-1.5 transition-all ${
              exploitOnly ? 'bg-neo-red text-white shadow-neb-xs' : 'bg-white shadow-neb-sm'
            }`}
          >
            <Bug className="w-3 h-3" /> Exploits
          </button>
        </div>
      </div>

      <div className="bg-white border-3 border-black shadow-neb divide-y-[3px] divide-black overflow-hidden">
        {loading ? (
          <SkeletonRegion label="Loading CVEs">
            <SkeletonRows rows={8} />
          </SkeletonRegion>
        ) : cves.length > 0 ? (
          cves.map((cve) => (
            <a
              key={cve.id}
              href={`/cve/${cve.cve_id}`}
              onClick={(e) => { e.preventDefault(); navigate(`/cve/${cve.cve_id}`) }}
              className="px-5 py-4 flex items-center justify-between hover:bg-gray-50 cursor-pointer transition-colors block"
              role="button"
              aria-label={`View details for ${cve.cve_id}`}
            >
              <div className="flex items-center gap-4 flex-1 min-w-0">
                <span className={`text-sm font-black font-mono ${severityColors[cve.severity] || 'text-gray-500'}`}>
                  {cve.cve_id}
                </span>
                <span className="text-sm truncate">{cve.description}</span>
                {cve.exploit_available && (
                  <span className="px-1.5 py-0.5 text-[10px] bg-neo-red text-white border-2 border-black font-black uppercase flex-shrink-0">EXPLOIT</span>
                )}
              </div>
              <div className="flex items-center gap-4 ml-4">
                <span className="text-lg font-black">{cve.cvss_score}</span>
                <ExternalLink className="w-4 h-4 text-gray-400" />
              </div>
            </a>
          ))
        ) : (
          <div className="p-8 text-center text-gray-400 text-sm font-bold uppercase">No CVEs found</div>
        )}
      </div>

      {/* Suppressed while loading: `cves` is still the empty initial state, so
          this rendered "0 results" underneath a list that was in fact loading
          -- a claim about the data that was not yet true. */}
      <div className="text-[10px] font-bold text-gray-400 text-center uppercase">
        {loading ? 'Searching…' : `${cves.length} results`}
      </div>
    </div>
  )
}
