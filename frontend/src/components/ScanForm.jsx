import { useState } from 'react'
import { Play, Loader2, Star } from 'lucide-react'

const scanners = [
  { id: 'nmap', label: 'Nmap', desc: 'Port scanning & service detection' },
  { id: 'nuclei', label: 'Nuclei', desc: 'Template-based vulnerability scanning' },
  { id: 'openvas', label: 'OpenVAS', desc: 'Comprehensive vulnerability assessment' },
  { id: 'nessus', label: 'Nessus', desc: 'Enterprise vulnerability scanner' },
  { id: 'burp', label: 'Burp Suite', desc: 'Web application security testing' },
  { id: 'zap', label: 'OWASP ZAP', desc: 'Dynamic application security testing' },
]

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
                <div className="text-sm font-bold text-black">{s.label}</div>
                <div className="text-[11px] text-gray-600 truncate">{s.desc}</div>
              </div>
            </label>
          ))}
        </div>
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
