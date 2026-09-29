import { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import { Search, Bug, SearchX, ChevronRight } from 'lucide-react'
import { searchCVEs } from '../api/client'
import { SkeletonRegion, SkeletonRows } from '../components/Skeleton'
import { Badge, Button, Card, EmptyState, Input, PageHeader, Segmented, SeverityBadge, cx } from '../components/ui'

const SEVERITIES = [
  { value: '', label: 'All' },
  { value: 'CRITICAL', label: 'Critical' },
  { value: 'HIGH', label: 'High' },
  { value: 'MEDIUM', label: 'Medium' },
  { value: 'LOW', label: 'Low' },
]

export default function CVEBrowse() {
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
    <div>
      <PageHeader title="CVE database" description="The vulnerabilities the assistant retrieves from, enriched with KEV and EPSS." />

      <div className="flex flex-col lg:flex-row gap-3 mb-4">
        <form onSubmit={handleSearch} role="search" className="flex gap-2 flex-1">
          <Input
            icon={Search}
            aria-label="Search CVE descriptions"
            className="flex-1 min-w-0"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search descriptions, e.g. deserialization"
          />
          <Button type="submit">Search</Button>
        </form>
        <div className="flex items-center gap-2 flex-wrap">
          <Segmented label="Severity" role="radiogroup" value={severity} onChange={setSeverity} options={SEVERITIES} />
          <button
            type="button"
            aria-pressed={exploitOnly}
            onClick={() => setExploitOnly(!exploitOnly)}
            className={cx(
              'inline-flex items-center gap-1.5 h-9 px-3 rounded-ctl border text-[13px] font-medium transition-colors duration-150',
              exploitOnly ? 'bg-crit-soft border-crit/30 text-crit' : 'bg-surface border-line text-ink-muted hover:text-ink hover:border-line-strong'
            )}
          >
            <Bug className="w-3.5 h-3.5" aria-hidden="true" /> Known exploit
          </button>
        </div>
      </div>

      <Card className="overflow-hidden">
        <div className="hidden md:grid grid-cols-[88px_150px_1fr_56px_16px] gap-4 px-5 py-2.5 border-b border-line bg-sunken text-xs text-ink-subtle">
          <span>Severity</span><span>ID</span><span>Description</span><span className="text-right">CVSS</span><span />
        </div>
        {loading ? (
          <SkeletonRegion label="Loading CVEs"><SkeletonRows rows={8} /></SkeletonRegion>
        ) : cves.length > 0 ? (
          <ul className="divide-y divide-line">
            {cves.map((cve) => (
              <li key={cve.id}>
                <Link
                  to={`/cve/${cve.cve_id}`}
                  className="grid grid-cols-[1fr_auto] md:grid-cols-[88px_150px_1fr_56px_16px] items-center gap-x-4 gap-y-1 px-5 py-3 hover:bg-hover transition-colors duration-150"
                >
                  <span className="hidden md:block"><SeverityBadge severity={cve.severity} /></span>
                  <span className="font-mono text-[13px] font-medium flex items-center gap-2">
                    <span className="md:hidden"><SeverityBadge severity={cve.severity} /></span>
                    {cve.cve_id}
                  </span>
                  <span className="col-span-2 md:col-span-1 row-start-2 md:row-start-auto text-[13px] text-ink-muted truncate flex items-center gap-2 min-w-0">
                    {cve.exploit_available && <Badge tone="crit" icon={Bug}>Exploit</Badge>}
                    <span className="truncate">{cve.description}</span>
                  </span>
                  <span className="text-sm font-semibold tabular text-right row-start-1 col-start-2 md:row-start-auto md:col-start-auto">{cve.cvss_score}</span>
                  <ChevronRight className="hidden md:block w-4 h-4 text-ink-subtle" aria-hidden="true" />
                </Link>
              </li>
            ))}
          </ul>
        ) : (
          <EmptyState icon={SearchX} title="No CVEs match">Try a broader search or clear the filters.</EmptyState>
        )}
      </Card>

      {/* Hidden while loading: "0 results" under a list that is still
          loading is a claim about the data that is not yet true. */}
      <p className="text-xs text-ink-subtle mt-3 tabular" aria-live="polite">
        {loading ? 'Searching…' : `${cves.length} results`}
      </p>
    </div>
  )
}
