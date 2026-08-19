import { useState, useEffect, useCallback } from 'react'
import {
  Network, Search, AlertTriangle, ArrowRight, ExternalLink, Layers, Info
} from 'lucide-react'
import { getGraphStats, getGraphChain, searchGraph } from '../api/client'

// The four layers, in the order the walk traverses them. Rendered as lanes
// rather than a force-directed graph: the relationship here is a fixed
// four-stage pipeline, and a hairball hides exactly the structure that makes
// it worth showing.
const LAYERS = [
  { key: 'cve', label: 'Vulnerability', sub: 'CVE', color: 'bg-neo-red text-white' },
  { key: 'weaknesses', label: 'Weakness class', sub: 'CWE', color: 'bg-neo-orange' },
  { key: 'patterns', label: 'Attack patterns', sub: 'CAPEC', color: 'bg-neo-yellow' },
  { key: 'techniques', label: 'Adversary techniques', sub: 'ATT&CK', color: 'bg-neo-cyan' },
]

const KIND_STYLE = {
  cve: 'bg-neo-red text-white',
  cwe: 'bg-neo-orange',
  capec: 'bg-neo-yellow',
  attack: 'bg-neo-cyan',
}

function LayerHeader({ layer, count }) {
  return (
    <div className="flex items-center justify-between mb-3">
      <div className="flex items-center gap-2 min-w-0">
        <span className={`px-2 py-0.5 text-[10px] font-black uppercase border-2 border-black ${layer.color}`}>
          {layer.sub}
        </span>
        <h3 className="text-xs font-black uppercase tracking-wider truncate">{layer.label}</h3>
      </div>
      <span className="text-[10px] font-black text-gray-500">{count}</span>
    </div>
  )
}

export default function KnowledgeGraph() {
  const [stats, setStats] = useState(null)
  const [query, setQuery] = useState('CVE-2021-44228')
  const [chain, setChain] = useState(null)
  const [results, setResults] = useState([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  useEffect(() => {
    getGraphStats()
      .then(({ data }) => setStats(data))
      .catch((err) => setError(err.message || 'Failed to read graph status'))
  }, [])

  const runLookup = useCallback(async (term) => {
    const value = (term || '').trim()
    if (!value) return
    setLoading(true)
    setError('')
    setChain(null)
    setResults([])
    try {
      if (/^CVE-\d{4}-\d{4,}$/i.test(value)) {
        const { data } = await getGraphChain(value.toUpperCase())
        setChain(data)
        if (!data.found) setError(`${value.toUpperCase()} is not in the graph.`)
      } else {
        const { data } = await searchGraph(value)
        setResults(data.results || [])
        if (!data.results?.length) setError(`Nothing matched "${value}".`)
      }
    } catch (err) {
      setError(err.response?.data?.detail || err.message || 'Lookup failed')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { runLookup('CVE-2021-44228') }, [runLookup])

  const graphMissing = stats && !stats.loaded

  return (
    <div className="space-y-6 min-w-0">
      <div>
        <h1 className="text-3xl font-black uppercase tracking-tight">Knowledge Graph</h1>
        <p className="text-sm font-bold text-gray-600 mt-1 uppercase tracking-wider">
          CVE &rarr; CWE &rarr; CAPEC &rarr; ATT&amp;CK
        </p>
      </div>

      {graphMissing && (
        <div className="bg-neo-yellow border-3 border-black p-4 shadow-neb">
          <div className="flex items-start gap-3">
            <AlertTriangle className="w-5 h-5 flex-shrink-0 mt-0.5" />
            <div className="min-w-0">
              <p className="font-black uppercase text-sm mb-1">Graph not built</p>
              <p className="text-xs font-bold mb-2">{stats.error}</p>
              <pre className="text-[11px] font-mono bg-white border-2 border-black p-2 overflow-x-auto">
python scripts/fetch_datasets.py{'\n'}python scripts/build_knowledge_graph.py
              </pre>
            </div>
          </div>
        </div>
      )}

      {stats?.loaded && (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
          {[
            { label: 'Nodes', value: stats.nodes, color: 'bg-neo-purple text-white' },
            { label: 'Edges', value: stats.edges, color: 'bg-neo-green' },
            { label: 'Weaknesses', value: stats.meta?.kinds?.cwe ?? 0, color: 'bg-neo-orange' },
            { label: 'Techniques', value: stats.meta?.kinds?.attack ?? 0, color: 'bg-neo-cyan' },
          ].map((card) => (
            <div key={card.label} className={`${card.color} border-3 border-black p-4 shadow-neb-sm`}>
              <div className="text-2xl font-black">{card.value}</div>
              <div className="text-[10px] font-bold uppercase tracking-wider opacity-70">{card.label}</div>
            </div>
          ))}
        </div>
      )}

      <form
        onSubmit={(e) => { e.preventDefault(); runLookup(query) }}
        className="flex flex-col sm:flex-row gap-2"
      >
        <div className="flex items-center gap-2 flex-1 min-w-0 bg-white border-3 border-black px-4 py-3 nb-input">
          <Search className="w-5 h-5 text-gray-400 flex-shrink-0" />
          <input
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="CVE-2021-44228, CWE-502, or a name like 'deserialization'"
            className="bg-transparent border-none outline-none text-black text-sm w-full placeholder-gray-400 font-mono"
          />
        </div>
        <button
          type="submit"
          disabled={loading || !query.trim()}
          className="px-6 py-3 bg-neo-purple text-white nb-btn disabled:bg-gray-300 disabled:text-gray-500 disabled:shadow-none text-sm flex-shrink-0"
        >
          {loading ? 'Looking up...' : 'Trace'}
        </button>
      </form>

      {error && !loading && (
        <div className="bg-white border-3 border-black p-4 shadow-neb flex items-center gap-3">
          <AlertTriangle className="w-5 h-5 text-neo-red flex-shrink-0" />
          <p className="text-sm font-bold">{error}</p>
        </div>
      )}

      {/* Search results, when the term was not a CVE */}
      {results.length > 0 && (
        <div className="bg-white border-3 border-black shadow-neb overflow-hidden">
          <div className="p-4 border-b-[3px] border-black bg-neo-green">
            <h3 className="text-sm font-black uppercase tracking-wider">{results.length} matches</h3>
          </div>
          <div className="divide-y-[3px] divide-black max-h-[420px] overflow-y-auto">
            {results.map((node) => (
              <div key={node.id} className="px-5 py-3">
                <div className="flex items-center gap-2 mb-1 flex-wrap">
                  <span className={`px-2 py-0.5 text-[10px] font-black uppercase border-2 border-black ${KIND_STYLE[node.kind] || 'bg-gray-200'}`}>
                    {node.id}
                  </span>
                  <span className="text-sm font-bold truncate">{node.name}</span>
                </div>
                {node.description && (
                  <p className="text-xs text-gray-600 font-medium line-clamp-2">{node.description}</p>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* The four-lane chain */}
      {chain?.found && (
        <>
          {chain.weaknesses.length === 0 && (
            <div className="bg-white border-3 border-black p-4 shadow-neb flex items-start gap-3">
              <Info className="w-5 h-5 flex-shrink-0 mt-0.5 text-gray-500" />
              <div className="text-xs font-bold">
                <p className="mb-1">{chain.cve} is in the graph but carries no CWE assignment.</p>
                <p className="text-gray-600 font-medium">
                  NVD has not assigned a weakness to this CVE, so there is no path onward to
                  attack patterns or techniques. This is a gap in the published data, not a
                  lookup failure.
                </p>
              </div>
            </div>
          )}

          <div className="grid grid-cols-1 lg:grid-cols-4 gap-4">
            {LAYERS.map((layer, idx) => {
              const items = layer.key === 'cve'
                ? [{ id: chain.cve, name: 'Reported vulnerability' }]
                : chain[layer.key] || []
              return (
                <div key={layer.key} className="bg-white border-3 border-black p-4 shadow-neb min-w-0">
                  <LayerHeader layer={layer} count={items.length} />
                  <div className="space-y-2">
                    {items.length === 0 && (
                      <p className="text-xs text-gray-400 font-bold uppercase py-4 text-center">None</p>
                    )}
                    {items.map((item) => (
                      <div key={item.id} className="border-2 border-black p-2 bg-gray-50">
                        <div className="flex items-center gap-1.5 mb-1 flex-wrap">
                          <span className={`px-1.5 py-0.5 text-[9px] font-black border-2 border-black ${layer.color}`}>
                            {item.id}
                          </span>
                          {item.severity && (
                            <span className="text-[9px] font-black uppercase text-gray-500">{item.severity}</span>
                          )}
                        </div>
                        <p className="text-xs font-bold leading-snug">{item.name}</p>
                        {item.tactics?.length > 0 && (
                          <p className="text-[10px] text-gray-500 font-mono mt-1">{item.tactics.join(', ')}</p>
                        )}
                        {item.url && (
                          <a
                            href={item.url}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="text-[10px] font-black uppercase inline-flex items-center gap-1 mt-1 hover:underline"
                          >
                            MITRE <ExternalLink className="w-3 h-3" />
                          </a>
                        )}
                      </div>
                    ))}
                  </div>
                  {idx < LAYERS.length - 1 && (
                    <div className="hidden lg:flex justify-end mt-2">
                      <ArrowRight className="w-4 h-4 text-gray-400" />
                    </div>
                  )}
                </div>
              )
            })}
          </div>

          {(chain.truncated?.patterns > 0 || chain.truncated?.techniques > 0) && (
            <p className="text-xs font-bold text-gray-500 uppercase tracking-wider">
              <Layers className="w-3 h-3 inline mr-1" />
              {chain.truncated.patterns} further patterns and {chain.truncated.techniques} further
              techniques were reached but not shown
            </p>
          )}

          {chain.tactics?.length > 0 && (
            <div className="bg-white border-3 border-black p-5 shadow-neb">
              <h3 className="text-sm font-black uppercase tracking-wider mb-3">
                <Network className="w-4 h-4 inline mr-2" />
                ATT&amp;CK tactics reachable from this vulnerability
              </h3>
              <div className="flex flex-wrap gap-2">
                {chain.tactics.map((tactic) => (
                  <span key={tactic} className="px-3 py-1 text-xs font-black uppercase border-2 border-black bg-neo-cyan">
                    {tactic.replace(/-/g, ' ')}
                  </span>
                ))}
              </div>
            </div>
          )}
        </>
      )}
    </div>
  )
}
