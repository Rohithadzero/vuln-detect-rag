import { useState, useEffect } from 'react'
import { getBackendLogs, getLLMStatus, getHealth } from '../api/client'
import { RefreshCw, Download, FileText, Settings as SettingsIcon, Cpu, AlertTriangle, CheckCircle, XCircle } from 'lucide-react'
import ProviderControls from '../components/ProviderControls'

export default function Settings() {
  const [logs, setLogs] = useState('')
  const [loading, setLoading] = useState(false)
  const [llmStatus, setLlmStatus] = useState(null)
  const [healthData, setHealthData] = useState(null)

  const fetchLogs = async () => {
    setLoading(true)
    try {
      const { data } = await getBackendLogs()
      setLogs(data.logs || 'No logs available yet.')
    } catch (err) { setLogs(`Error fetching logs: ${err.message}`) } finally { setLoading(false) }
  }

  const fetchStatus = async () => {
    try {
      const [llmRes, healthRes] = await Promise.all([getLLMStatus(), getHealth()])
      setLlmStatus(llmRes.data)
      setHealthData(healthRes.data)
    } catch (err) { console.error('Failed to fetch status:', err) }
  }

  useEffect(() => {
    fetchLogs(); fetchStatus()
    const interval = setInterval(fetchLogs, 5000)
    return () => clearInterval(interval)
  }, [])

  return (
    <div className="space-y-6 flex flex-col h-full min-h-0 min-w-0">
      <div className="flex flex-col sm:flex-row sm:items-center gap-3 pb-4 border-b-[3px] border-black">
        <div className="p-2 bg-neo-pink border-3 border-black shadow-[4px_4px_0px_0px_#000] flex-shrink-0 self-start">
          <SettingsIcon className="w-6 h-6" />
        </div>
        <div className="min-w-0">
          <h1 className="text-3xl font-black uppercase tracking-tight">Settings</h1>
          <p className="text-sm font-bold text-gray-600 uppercase tracking-wider">Platform configuration and logs</p>
        </div>
      </div>

      {/* Research controls: per-provider toggles, model choice, RAG on/off */}
      <ProviderControls />

      {/* Status Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div className="bg-white border-3 border-black p-4 shadow-[6px_6px_0px_0px_#000]">
          <div className="flex items-center gap-2 mb-3">
            <Cpu className="w-5 h-5" />
            <h3 className="text-sm font-black uppercase">Local LLM Status</h3>
          </div>
          {llmStatus ? (
            <div className="space-y-2">
              <div className="flex items-center gap-2">
                {llmStatus.available ? (
                  <CheckCircle className="w-4 h-4 text-green-600" />
                ) : (
                  <AlertTriangle className="w-4 h-4 text-neo-red" />
                )}
                <span className={`font-black text-sm ${llmStatus.available ? 'text-green-700' : 'text-neo-red'}`}>
                  {llmStatus.available ? 'Connected' : 'LOCAL LLM NOT FOUND'}
                </span>
              </div>
              {llmStatus.available && (
                <>
                  <div className="text-sm">
                    <span className="font-bold text-gray-500">Model:</span>{' '}
                    <code className="bg-gray-100 border-2 border-black px-1.5 py-0.5 text-xs font-mono font-bold">{llmStatus.model}</code>
                  </div>
                  <div className="text-sm">
                    <span className="font-bold text-gray-500">Provider:</span> Ollama
                  </div>
                </>
              )}
              {llmStatus.models && llmStatus.models.length > 0 && (
                <div className="text-sm">
                  <span className="font-bold text-gray-500">Installed:</span>{' '}
                  <span className="font-mono text-xs">{llmStatus.models.join(', ')}</span>
                </div>
              )}
              {!llmStatus.available && (
                <p className="text-xs font-bold text-gray-400 mt-2">
                  Run <code className="bg-gray-100 border-2 border-black px-1 py-0.5 font-mono">ollama pull qwen2.5-coder:7b</code> to install
                </p>
              )}
            </div>
          ) : (
            <p className="text-sm font-bold text-gray-400">Loading...</p>
          )}
        </div>

        <div className="bg-white border-3 border-black p-4 shadow-[6px_6px_0px_0px_#000]">
          <div className="flex items-center gap-2 mb-3">
            <SettingsIcon className="w-5 h-5" />
            <h3 className="text-sm font-black uppercase">Scanner Status</h3>
          </div>
          {healthData ? (
            <div className="space-y-2">
              {Object.entries(healthData.scanners || {}).map(([name, available]) => (
                <div key={name} className="flex items-center gap-2">
                  {available ? (
                    <CheckCircle className="w-4 h-4 text-green-600" />
                  ) : (
                    <XCircle className="w-4 h-4 text-gray-300" />
                  )}
                  <span className={`text-xs font-bold uppercase ${available ? '' : 'text-gray-400'}`}>{name}</span>
                </div>
              ))}
              <div className="text-[10px] font-bold text-gray-400 uppercase mt-2">Version: {healthData.version}</div>
            </div>
          ) : (
            <p className="text-sm font-bold text-gray-400">Loading...</p>
          )}
        </div>
      </div>

      {/* Log Viewer */}
      <div className="flex-1 flex flex-col bg-white border-3 border-black shadow-[6px_6px_0px_0px_#000] overflow-hidden min-h-0">
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between p-4 border-b-[3px] border-black bg-neo-yellow gap-3">
          <div className="flex items-center gap-2 font-black uppercase text-sm">
            <FileText className="w-5 h-5 flex-shrink-0" />
            <span>Backend Live Logs</span>
          </div>
          <div className="flex items-center gap-3 flex-shrink-0">
            <button onClick={fetchLogs} disabled={loading} className="px-3 py-1.5 bg-white border-3 border-black text-[10px] font-black uppercase nb-btn flex items-center gap-2">
              <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} /> Refresh
            </button>
            <button onClick={() => {
              const blob = new Blob([logs], { type: 'text/plain' })
              const url = URL.createObjectURL(blob)
              const a = document.createElement('a')
              a.href = url; a.download = 'vulndetect-backend.log'; a.click()
              URL.revokeObjectURL(url)
            }} className="px-3 py-1.5 bg-neo-cyan border-3 border-black text-[10px] font-black uppercase nb-btn flex items-center gap-2">
              <Download className="w-4 h-4" /> Download
            </button>
          </div>
        </div>

        <div className="flex-1 overflow-auto bg-black p-4 text-xs font-mono text-green-400 leading-relaxed min-h-0">
          <pre className="whitespace-pre-wrap break-all overflow-hidden">{logs}</pre>
        </div>
      </div>
    </div>
  )
}
