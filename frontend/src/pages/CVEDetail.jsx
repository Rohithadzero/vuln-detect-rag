import { useState, useEffect } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { ArrowLeft, ShieldQuestion, ExternalLink, Bug, Wrench } from 'lucide-react'
import { getCVE } from '../api/client'
import { sanitizeUrl } from '../utils/sanitize'
import Skeleton, { SkeletonRegion, SkeletonText, SkeletonCard } from '../components/Skeleton'
import { Badge, Button, Card, CardHeader, EmptyState, SeverityBadge, SEVERITY_TONE } from '../components/ui'

export default function CVEDetail() {
  const { cveId } = useParams()
  const navigate = useNavigate()
  const [cve, setCve] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  useEffect(() => { loadCVE() }, [cveId])

  const loadCVE = async () => {
    setLoading(true); setError(null)
    try {
      const { data } = await getCVE(cveId)
      setCve(data)
    } catch (err) {
      setError(err.response?.data?.detail || 'CVE not found')
    } finally { setLoading(false) }
  }

  const back = (
    <Button variant="ghost" size="sm" icon={ArrowLeft} onClick={() => navigate(-1)} className="-ml-2 mb-4">
      Back
    </Button>
  )

  if (loading) {
    return (
      <SkeletonRegion label="Loading CVE details" className="space-y-4">
        <Skeleton className="h-8 w-20" />
        <Card className="p-6 space-y-4">
          <Skeleton className="h-6 w-56" />
          <SkeletonText lines={3} />
        </Card>
        <SkeletonCard lines={3} />
      </SkeletonRegion>
    )
  }

  if (error) {
    return (
      <div>
        {back}
        <Card>
          <EmptyState icon={ShieldQuestion} title={error}>
            <span className="font-mono">{cveId}</span> is not in the local database.
          </EmptyState>
        </Card>
      </div>
    )
  }

  const tone = SEVERITY_TONE[cve.severity] || 'neutral'

  return (
    <div>
      {back}

      <Card className="p-6 mb-6">
        <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-4">
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2 mb-1.5">
              <h1 className="text-2xl font-semibold font-mono tracking-tight">{cve.cve_id}</h1>
              <SeverityBadge severity={cve.severity} />
              {cve.exploit_available && <Badge tone="crit" icon={Bug}>Known exploit</Badge>}
            </div>
            <p className="text-[13px] text-ink-muted">Source: {cve.source}</p>
          </div>
          <div className="sm:text-right flex-shrink-0">
            <div className={`text-3xl font-semibold tabular text-${tone === 'neutral' ? 'ink' : tone}`}>{cve.cvss_score}</div>
            <div className="text-xs text-ink-subtle">CVSS base score</div>
          </div>
        </div>
      </Card>

      <div className="grid grid-cols-1 lg:grid-cols-5 gap-6">
        <Card className="lg:col-span-3">
          <CardHeader title="Description" />
          <p className="px-5 pb-5 text-sm leading-relaxed break-words max-w-prose">{cve.description}</p>
        </Card>
        <Card className="lg:col-span-2">
          <CardHeader title="Remediation" icon={Wrench} />
          <p className="px-5 pb-5 text-sm leading-relaxed break-words">
            {cve.solution || <span className="text-ink-muted">No remediation guidance recorded for this CVE.</span>}
          </p>
        </Card>
      </div>

      {cve.references?.length > 0 && (
        <Card className="mt-6">
          <CardHeader title="References" description={`${cve.references.length} links`} />
          <ul className="px-5 pb-5 space-y-1.5">
            {cve.references.map((ref, i) => {
              const safeHref = sanitizeUrl(ref)
              return (
                <li key={i} className="min-w-0 text-[13px]">
                  {safeHref ? (
                    <a href={safeHref} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-2 text-accent-text hover:underline max-w-full">
                      <ExternalLink className="w-3.5 h-3.5 flex-shrink-0" aria-hidden="true" />
                      <span className="truncate">{ref}</span>
                    </a>
                  ) : (
                    <span className="text-ink-subtle break-all">{ref}</span>
                  )}
                </li>
              )
            })}
          </ul>
        </Card>
      )}
    </div>
  )
}
