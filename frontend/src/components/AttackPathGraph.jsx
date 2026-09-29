import { GitBranch, ChevronRight, AlertTriangle, Server, Plug } from 'lucide-react'
import { Badge, Card, EmptyState, SEVERITY_TONE, cx } from './ui'

const NODE = {
  host: { icon: Server, cls: 'bg-sunken border-line text-ink' },
  service: { icon: Plug, cls: 'bg-low-soft border-low/20 text-ink' },
  vulnerability: { icon: AlertTriangle, cls: 'bg-crit-soft border-crit/20 text-ink' },
}

export default function AttackPathGraph({ paths }) {
  if (!paths || paths.length === 0) {
    return (
      <Card>
        <EmptyState icon={GitBranch} title="No attack paths identified">
          Paths appear when findings on the same host can be chained, for example an exposed service with a known exploit.
        </EmptyState>
      </Card>
    )
  }

  return (
    <Card className="overflow-hidden">
      <ul className="divide-y divide-line">
        {paths.map((path, i) => (
          <li key={i} className="px-5 py-4">
            <div className="flex items-center justify-between gap-3 mb-3">
              <span className="font-mono text-[13px] font-medium truncate">{path.path_id}</span>
              <div className="flex items-center gap-2 flex-shrink-0">
                <Badge tone={SEVERITY_TONE[path.risk_level] || 'neutral'}>{path.risk_level}</Badge>
                <span className="text-xs text-ink-muted tabular">CVSS {path.total_cvss}</span>
              </div>
            </div>

            <ol className="flex items-center gap-1.5 overflow-x-auto pb-1" aria-label="Path steps">
              {path.nodes.map((node, j) => {
                const style = NODE[node.type] || NODE.host
                return (
                  <li key={j} className="flex items-center gap-1.5 flex-shrink-0">
                    <span
                      className={cx('inline-flex items-center gap-1.5 h-7 px-2.5 rounded-full border text-xs max-w-[220px]', style.cls)}
                      title={node.label}
                    >
                      <style.icon className="w-3 h-3 flex-shrink-0 text-ink-subtle" aria-hidden="true" />
                      <span className="truncate">{node.label}</span>
                    </span>
                    {j < path.nodes.length - 1 && <ChevronRight className="w-3.5 h-3.5 text-ink-subtle" aria-hidden="true" />}
                  </li>
                )
              })}
            </ol>

            {path.edges?.length > 0 && (
              <ul className="mt-2 space-y-0.5">
                {path.edges.map((edge, j) => (
                  <li key={j} className="text-xs font-mono text-ink-subtle truncate">
                    {edge.source.split(':')[1]} → {edge.target.split(':')[1]}
                    {edge.label && <span> ({edge.label})</span>}
                  </li>
                ))}
              </ul>
            )}
          </li>
        ))}
      </ul>
    </Card>
  )
}
