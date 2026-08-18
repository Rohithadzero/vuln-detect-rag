import { useState } from 'react'
import { Play, Loader2, Star } from 'lucide-react'

// `status` is shown next to each checkbox so the user knows, before starting a
// scan, whether a tool can actually run. Presenting a simulated scanner as if
// it were live is the single most misleading thing this UI could do.
const scanners = [
  { id: 'nmap', label: 'Nmap', desc: 'Port scanning & service detection', status: 'live', free: true },
  { id: 'nuclei', label: 'Nuclei', desc: 'Template-based vulnerability scanning', status: 'live', free: true },
  { id: 'zap', label: 'OWASP ZAP', desc: 'Dynamic application security testing', status: 'live', free: true },
  { id: 'openvas', label: 'OpenVAS', desc: 'Comprehensive vulnerability assessment', status: 'live', free: true, note: 'Needs a running GVM/openvas stack' },
  { id: 'burp', label: 'Burp Suite', desc: 'Web application security testing', status: 'licence', free: false, note: 'Requires a Burp Pro licence; Community has no automation API' },
  { id: 'nessus', label: 'Nessus', desc: 'Enterprise vulnerability scanner', status: 'simulated', free: false, note: 'Simulated - not a live scan' },
]

const STATUS_STYLES = {
  live: 'bg-neo-green',
  licence: 'bg-neo-yellow',
  simulated: 'bg-neo-orange',
}

const STATUS_LABELS = {
  live: 'Live',
  licence: 'Paid licence',
  simulated: 'Simulated',
}

const defaultScanners = ['nmap', 'nuclei']

export default function ScanForm({ onStartScan, loading, onAddFavorite }) {
  const [target, setTarget] = useState('')
  const [selected, setSelected] = useState(defaultScanners)

  const toggleScanner = (id) => {
    setSelected((prev) =>
      prev.includes(id) ? prev.filter((s) => s !== id) : [...prev, id]
    )
  }

  const handleSubmit = (e) => {
    e.preventDefault()
    if (!target.trim() || selected.length === 0) return
    onStartScan(target.trim(), selected)
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <div>
        <label className="block text-sm font-bold text-black mb-2 uppercase tracking-wide">
          Target Domain or IP
        </label>
        <div className="flex gap-2">
          <input
            type="text"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder="e.g., example.com or 192.168.1.1"
            className="flex-1 min-w-0 bg-white border-3 border-black rounded-none px-4 py-3 text-black placeholder-gray-500 focus:outline-none font-mono shadow-[4px_4px_0px_0px_#000] focus:shadow-[2px_2px_0px_0px_#000] transition-shadow"
            disabled={loading}
          />
          {target.trim() && onAddFavorite && (
            <button
              type="button"
              onClick={() => onAddFavorite(target.trim())}
              className="px-3 bg-yellow-300 border-3 border-black text-black hover:bg-yellow-400 transition-colors flex-shrink-0 shadow-[4px_4px_0px_0px_#000] active:shadow-[2px_2px_0px_0px_#000]"
              title="Save to favorites"
            >
              <Star className="w-4 h-4" />
            </button>
          )}
        </div>
      </div>

      <div>
        <label className="block text-sm font-bold text-black mb-2 uppercase tracking-wide">
          Select Scanners
        </label>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          {scanners.map((s) => (
            <label
              key={s.id}
              className={`flex items-center gap-3 p-3 border-3 border-black cursor-pointer transition-all ${
                selected.includes(s.id)
                  ? 'bg-cyan-300 shadow-[2px_2px_0px_0px_#000] translate-x-[-2px] translate-y-[-2px]'
                  : 'bg-white hover:bg-gray-100 shadow-[4px_4px_0px_0px_#000]'
              }`}
            >
              <input
                type="checkbox"
                checked={selected.includes(s.id)}
                onChange={() => toggleScanner(s.id)}
                className="sr-only"
              />
              <div
                className={`w-5 h-5 border-3 border-black flex items-center justify-center flex-shrink-0 ${
                  selected.includes(s.id) ? 'bg-black' : 'bg-white'
                }`}
              >
                {selected.includes(s.id) && (
                  <svg className="w-3 h-3 text-cyan-300" viewBox="0 0 12 12">
                    <path
                      d="M10 3L4.5 8.5 2 6"
                      stroke="currentColor"
                      strokeWidth="2.5"
                      fill="none"
                      strokeLinecap="round"
                      strokeLinejoin="round"
                    />
                  </svg>
                )}
              </div>
              <div className="min-w-0">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="text-sm font-bold text-black">{s.label}</span>
                  <span
                    className={`text-[9px] font-black uppercase px-1.5 py-0.5 border-2 border-black ${STATUS_STYLES[s.status]}`}
                  >
                    {STATUS_LABELS[s.status]}
                  </span>
                  {s.free && (
                    <span className="text-[9px] font-black uppercase text-green-700">
                      Free
                    </span>
                  )}
                </div>
                <div className="text-[11px] text-gray-600 truncate">{s.desc}</div>
                {s.note && (
                  <div className="text-[10px] font-bold text-gray-500 mt-0.5">
                    {s.note}
                  </div>
                )}
              </div>
            </label>
          ))}
        </div>

        {selected.some((id) => scanners.find((s) => s.id === id)?.status !== 'live') && (
          <p className="mt-3 text-[11px] font-bold bg-neo-orange border-3 border-black p-2">
            One or more selected tools cannot run live here and will return
            simulated sample data. Those findings are labelled &quot;Simulated&quot;
            in the results and do not describe the real target.
          </p>
        )}
      </div>

      <button
        type="submit"
        disabled={loading || !target.trim() || selected.length === 0}
        className="w-full flex items-center justify-center gap-2 px-4 py-3 bg-red-500 hover:bg-red-400 disabled:bg-gray-300 disabled:text-gray-500 text-white font-black uppercase tracking-wider border-3 border-black shadow-[6px_6px_0px_0px_#000] hover:shadow-[3px_3px_0px_0px_#000] active:shadow-[1px_1px_0px_0px_#000] hover:translate-x-[-3px] hover:translate-y-[-3px] active:translate-x-[0px] active:translate-y-[0px] transition-all"
      >
        {loading ? (
          <>
            <Loader2 className="w-5 h-5 animate-spin" />
            Scanning...
          </>
        ) : (
          <>
            <Play className="w-5 h-5" />
            Start Scan
          </>
        )}
      </button>
    </form>
  )
}
