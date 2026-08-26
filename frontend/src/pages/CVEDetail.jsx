import { useState, useEffect } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { ArrowLeft, Shield, ExternalLink, Bug } from 'lucide-react'
import { getCVE } from '../api/client'
import { sanitizeUrl } from '../utils/sanitize'
import Skeleton, { SkeletonRegion, SkeletonText, SkeletonCard } from '../components/Skeleton'

const severityColors = {
  CRITICAL: 'bg-severity-critical',
  HIGH: 'bg-severity-high',
  MEDIUM: 'bg-severity-medium',
  LOW: 'bg-severity-low',
}

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

  if (loading) {
    return (
      <SkeletonRegion label="Loading CVE details" className="space-y-4">
        <Skeleton className="h-3 w-20" />
        <div className="bg-white border-3 border-black p-6 shadow-neb space-y-4">
          <div className="flex items-center gap-3">
            <Skeleton className="h-6 w-44" />
            <Skeleton className="h-5 w-20" />
          </div>
          <SkeletonText lines={4} />
        </div>
        <SkeletonCard lines={3} />
      </SkeletonRegion>
    )
  }

  if (error) {
    return (
      <div className="space-y-4">
        <button onClick={() => navigate(-1)} className="flex items-center gap-2 text-sm font-bold hover:text-neo-red uppercase">
          <ArrowLeft className="w-4 h-4" /> Back
        </button>
        <div className="bg-white border-3 border-black p-12 text-center shadow-[6px_6px_0px_0px_#000]">
          <Shield className="w-12 h-12 mx-auto mb-4 text-gray-300" />
          <p className="text-xl font-black text-neo-red uppercase">{error}</p>
          <p className="text-sm font-bold text-gray-500 mt-2">{cveId} was not found in the database</p>
        </div>
      </div>
    )
  }

  const severityClass = severityColors[cve.severity] || severityColors.LOW

  return (
    <div className="space-y-6">
      <button onClick={() => navigate(-1)} className="flex items-center gap-2 text-sm font-bold hover:text-neo-red uppercase">
        <ArrowLeft className="w-4 h-4" /> Back
      </button>

      <div className="bg-white border-3 border-black p-4 sm:p-6 shadow-[6px_6px_0px_0px_#000]">
        <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-4">
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2 mb-2">
              <h1 className="text-xl sm:text-2xl font-black font-mono truncate">{cve.cve_id}</h1>
              <span className={`px-2 py-1 text-[10px] font-black uppercase border-2 border-black ${severityClass}`}>
                {cve.severity}
              </span>
              {cve.exploit_available && (
                <span className="px-2 py-1 text-[10px] bg-neo-red text-white border-2 border-black font-black uppercase flex items-center gap-1">
                  <Bug className="w-3 h-3" /> EXPLOIT
                </span>
              )}
            </div>
            <p className="text-xs font-bold text-gray-500 uppercase">Source: {cve.source}</p>
          </div>
          <div className="text-left sm:text-right flex-shrink-0">
            <div className="text-3xl sm:text-4xl font-black">{cve.cvss_score}</div>
            <div className="text-[10px] font-black uppercase text-gray-500">CVSS Score</div>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-white border-3 border-black p-5 shadow-[4px_4px_0px_0px_#000]">
          <h3 className="text-xs font-black uppercase mb-3">Description</h3>
          <p className="text-sm leading-relaxed break-words">{cve.description}</p>
        </div>
        <div className="bg-white border-3 border-black p-5 shadow-[4px_4px_0px_0px_#000]">
          <h3 className="text-xs font-black uppercase mb-3">Remediation</h3>
          <p className="text-sm text-green-700 bg-green-50 border-2 border-green-700 p-2 leading-relaxed break-words font-bold">
            {cve.solution || 'No remediation info available'}
          </p>
        </div>
      </div>

      {cve.references?.length > 0 && (
        <div className="bg-white border-3 border-black p-5 shadow-[4px_4px_0px_0px_#000]">
          <h3 className="text-xs font-black uppercase mb-3">References</h3>
          <div className="space-y-2">
            {cve.references.map((ref, i) => {
              const safeHref = sanitizeUrl(ref)
              return safeHref ? (
                <a key={i} href={safeHref} target="_blank" rel="noopener noreferrer"
                  className="flex items-center gap-2 text-sm text-blue-600 hover:text-blue-800 font-bold">
                  <ExternalLink className="w-4 h-4" /> {ref}
                </a>
              ) : (
                <span key={i} className="flex items-center gap-2 text-sm text-gray-400">{ref}</span>
              )
            })}
          </div>
        </div>
      )}
    </div>
  )
}
