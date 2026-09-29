import { useState, useEffect } from 'react'
import { getBackendLogs, getLLMStatus, getHealth } from '../api/client'
import { RefreshCw, Download, HardDrive, Server } from 'lucide-react'
import ProviderControls from '../components/ProviderControls'
import MetricsPanel from '../components/MetricsPanel'
import ThemePicker from '../components/ThemePicker'
import ScannerStatus from '../components/ScannerStatus'
import { Badge, Button, Card, CardHeader, PageHeader } from '../components/ui'

function Section({ title, description, children }) {
  return (
    <section className="grid grid-cols-1 lg:grid-cols-[220px_1fr] gap-4 lg:gap-8 py-8 first:pt-0 border-b border-line last:border-0">
      <div>
        <h2 className="text-sm font-semibold">{title}</h2>
        {description && <p className="text-[13px] text-ink-muted mt-1">{description}</p>}
      </div>
      <div className="min-w-0 space-y-4">{children}</div>
    </section>
  )
}

export default function Settings() {
  const [logs, setLogs] = useState('')
  const [loading, setLoading] = useState(false)
  const [llmStatus, setLlmStatus] = useState(null)
  const [healthData, setHealthData] = useState(undefined)

  const fetchLogs = async () => {
    setLoading(true)
    try {
      const { data } = await getBackendLogs()
      setLogs(data.logs || 'No logs yet.')
    } catch (err) { setLogs(`Could not fetch logs: ${err.message}`) } finally { setLoading(false) }
  }

  const fetchStatus = async () => {
    try {
      const [llmRes, healthRes] = await Promise.all([getLLMStatus(), getHealth()])
      setLlmStatus(llmRes.data)
      setHealthData(healthRes.data)
    } catch {
      setHealthData(null)
    }
  }

  useEffect(() => {
    fetchLogs(); fetchStatus()
    const interval = setInterval(() => { if (!document.hidden) fetchLogs() }, 5000)
    return () => clearInterval(interval)
  }, [])

  const downloadLogs = () => {
    const blob = new Blob([logs], { type: 'text/plain' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url; a.download = 'vulndetect-backend.log'; a.click()
    URL.revokeObjectURL(url)
  }

  // Ollama is the offline fallback. It being absent is normal when cloud
  // providers are configured, so it is reported neutrally, not as an error.
  const ollamaUp = llmStatus && !llmStatus.error && (llmStatus.models?.length > 0)

  return (
    <div>
      <PageHeader title="Settings" description="Appearance, model providers, evaluation results and backend logs." />

      <Section title="Appearance" description="Applies immediately and is remembered on this device.">
        <ThemePicker />
      </Section>

      <Section title="Models" description="Enable providers, pick models, and switch retrieval off to measure the no-RAG baseline.">
        <ProviderControls />
      </Section>

      <Section title="Evaluation" description="Results from the last scripts/run_eval.py run.">
        <MetricsPanel />
      </Section>

      <Section title="System" description="What this machine can actually run.">
        <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
          <Card>
            <CardHeader title="Offline fallback" icon={HardDrive} />
            <div className="px-5 pb-5 text-[13px] space-y-2">
              {!llmStatus ? (
                <p className="text-ink-muted">Checking…</p>
              ) : ollamaUp ? (
                <>
                  <p className="flex items-center gap-2"><Badge tone="ok">Running</Badge> Ollama</p>
                  <p className="text-ink-muted">Installed: <span className="font-mono">{llmStatus.models.join(', ')}</span></p>
                </>
              ) : (
                <>
                  <p className="flex items-center gap-2"><Badge>Not running</Badge> Ollama</p>
                  <p className="text-ink-muted">
                    Cloud providers answer as normal. For offline use, install Ollama and run{' '}
                    <code className="font-mono text-ink bg-sunken px-1 py-0.5 rounded">ollama pull qwen2.5-coder:7b</code>.
                  </p>
                </>
              )}
              {llmStatus?.active_provider && (
                <p className="text-ink-muted pt-1">
                  Answering now: <span className="font-mono text-ink">{llmStatus.active_provider} / {llmStatus.active_model}</span>
                </p>
              )}
            </div>
          </Card>
          <Card>
            <CardHeader title="Scanners" icon={Server} description={healthData?.version ? `Backend v${healthData.version}` : undefined} />
            {healthData === undefined ? <p className="px-5 pb-5 text-[13px] text-ink-muted">Checking…</p> : <ScannerStatus health={healthData} />}
          </Card>
        </div>
      </Section>

      <Section title="Logs" description="Backend output, refreshed every 5 seconds while this tab is visible.">
        <Card className="overflow-hidden">
          <div className="flex items-center justify-between gap-3 px-4 py-2.5 border-b border-line">
            <span className="text-[13px] font-medium">backend.log</span>
            <div className="flex gap-2">
              <Button size="sm" variant="ghost" icon={RefreshCw} loading={loading} onClick={fetchLogs}>Refresh</Button>
              <Button size="sm" icon={Download} onClick={downloadLogs}>Download</Button>
            </div>
          </div>
          <pre className="h-[360px] overflow-auto bg-sunken px-4 py-3 text-xs leading-relaxed text-ink-muted whitespace-pre-wrap break-all">
            {logs}
          </pre>
        </Card>
      </Section>
    </div>
  )
}
