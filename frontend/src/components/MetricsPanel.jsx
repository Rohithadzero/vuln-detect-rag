import { BarChart3 } from 'lucide-react'

const colorMap = {
  green: 'bg-neo-green',
  blue: 'bg-neo-cyan',
  purple: 'bg-neo-purple',
}

export default function MetricsPanel({ metrics }) {
  if (!metrics) {
    return (
      <div className="text-center py-8 text-gray-400">
        <BarChart3 className="w-8 h-8 mx-auto mb-2" />
        <p className="font-bold uppercase">No evaluation metrics available</p>
      </div>
    )
  }

  const metricItems = [
    { label: 'CVE Detection F1', value: metrics.detection_f1, color: 'green' },
    { label: 'BLEU Score', value: metrics.bleu, color: 'blue' },
    { label: 'ROUGE Score', value: metrics.rouge, color: 'purple' },
  ]

  return (
    <div className="space-y-4">
      <h3 className="text-lg font-black uppercase flex items-center gap-2">
        <BarChart3 className="w-5 h-5" />
        Evaluation Metrics
      </h3>

      <div className="grid grid-cols-3 gap-4">
        {metricItems.map(({ label, value, color }) => (
          <div key={label} className="bg-white border-3 border-black p-4 shadow-[4px_4px_0px_0px_#000]">
            <div className="text-[10px] font-black uppercase tracking-wider mb-2">{label}</div>
            <div className="text-3xl font-black">{((value || 0) * 100).toFixed(1)}%</div>
            <div className="mt-2 h-3 bg-gray-200 border-2 border-black overflow-hidden">
              <div className={`h-full ${colorMap[color]}`} style={{ width: `${(value || 0) * 100}%` }} />
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}
