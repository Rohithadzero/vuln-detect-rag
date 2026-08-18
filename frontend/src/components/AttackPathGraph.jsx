import { GitBranch, AlertTriangle } from 'lucide-react'

const nodeColors = {
  host: 'bg-neo-cyan',
  vulnerability: 'bg-neo-red',
  service: 'bg-neo-orange',
}

export default function AttackPathGraph({ paths }) {
  if (!paths || paths.length === 0) {
    return (
      <div className="text-center py-8 text-gray-400">
        <GitBranch className="w-8 h-8 mx-auto mb-2" />
        <p className="font-black uppercase">No attack paths identified</p>
      </div>
    )
  }

  return (
    <div className="space-y-4 min-w-0">
      <h3 className="text-lg font-black uppercase flex items-center gap-2">
        <GitBranch className="w-5 h-5" />
        Attack Paths ({paths.length})
      </h3>

      {paths.map((path, i) => (
        <div key={i} className="bg-white border-3 border-black shadow-[4px_4px_0px_0px_#000] p-4 overflow-hidden">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-3">
            <span className="text-sm font-black uppercase font-mono">{path.path_id}</span>
            <div className="flex items-center gap-2 flex-shrink-0">
              <span className={`px-2 py-0.5 text-[10px] font-black uppercase border-2 border-black ${
                path.risk_level === 'CRITICAL' ? 'bg-neo-red text-white' :
                path.risk_level === 'HIGH' ? 'bg-neo-orange' : 'bg-neo-yellow'
              }`}>
                {path.risk_level}
              </span>
              <span className="text-sm font-bold">CVSS: {path.total_cvss}</span>
            </div>
          </div>

          <div className="flex items-center gap-2 overflow-x-auto pb-2 -mx-1 px-1">
            {path.nodes.map((node, j) => (
              <div key={j} className="flex items-center gap-2 flex-shrink-0">
                <div
                  className={`px-2 sm:px-3 py-1.5 sm:py-2 border-2 border-black text-[10px] sm:text-xs font-bold text-black max-w-[140px] sm:max-w-[200px] truncate ${nodeColors[node.type] || 'bg-gray-300'}`}
                  title={node.label}
                >
                  {node.type === 'vulnerability' && <AlertTriangle className="w-3 h-3 inline mr-1" />}
                  {node.label}
                </div>
                {j < path.nodes.length - 1 && (
                  <span className="text-2xl font-black">→</span>
                )}
              </div>
            ))}
          </div>

          <div className="mt-2 space-y-1">
            {path.edges.map((edge, j) => (
              <div key={j} className="text-[10px] font-bold font-mono text-gray-500 uppercase truncate">
                {edge.source.split(':')[1]} → {edge.target.split(':')[1]}
                {edge.label && <span className="text-gray-400"> ({edge.label})</span>}
              </div>
            ))}
          </div>
        </div>
      ))}
    </div>
  )
}
