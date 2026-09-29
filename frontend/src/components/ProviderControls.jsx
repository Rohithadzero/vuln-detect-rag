import { useState, useEffect } from 'react'
import { Cloud, HardDrive, Database, AlertTriangle } from 'lucide-react'
import {
  getProviders, toggleProvider, getProviderModels, setProviderModel,
  getRagConfig, setRagConfig,
} from '../api/client'
import Skeleton, { SkeletonRegion } from './Skeleton'
import { Badge, Callout, Card, CardHeader, Select, Toggle } from './ui'

const PROVIDER_LABELS = {
  groq: 'Groq',
  gemini: 'Google Gemini',
  openrouter: 'OpenRouter',
  nvidia: 'NVIDIA NIM',
  ollama: 'Ollama',
}

const PROVIDER_NOTES = {
  groq: 'Free tier, fastest responses',
  gemini: 'Free tier, large context',
  openrouter: 'Free models only; paid models are refused',
  nvidia: 'Free tier, widest model catalogue',
  ollama: 'Runs offline; nothing leaves this machine',
}

/**
 * Research controls: enable or disable each LLM backend, pick a model, and
 * turn retrieval on or off. Comparing backends only means something if the
 * others can be switched off, and the knowledge base's contribution can only
 * be shown by asking the same questions with retrieval disabled.
 */
export default function ProviderControls() {
  const [data, setData] = useState(null)
  const [rag, setRag] = useState(null)
  const [models, setModels] = useState({})
  const [busy, setBusy] = useState('')
  const [error, setError] = useState('')

  const load = async () => {
    try {
      const [providersRes, ragRes] = await Promise.all([getProviders(), getRagConfig()])
      setData(providersRes.data)
      setRag(ragRes.data)
      setError('')
    } catch (err) {
      setError(err.message || 'Could not load provider settings')
    }
  }

  useEffect(() => { load() }, [])

  const handleToggle = async (provider, enabled) => {
    setBusy(provider)
    try {
      await toggleProvider(provider, enabled)
      await load()
    } catch (err) {
      setError(err.message || `Could not toggle ${provider}`)
    } finally { setBusy('') }
  }

  const handleRagToggle = async (enabled) => {
    setBusy('rag')
    try {
      await setRagConfig(enabled)
      await load()
    } catch (err) {
      setError(err.message || 'Could not toggle retrieval')
    } finally { setBusy('') }
  }

  const loadModels = async (provider) => {
    if (models[provider]) return
    try {
      const { data } = await getProviderModels(provider)
      setModels((prev) => ({ ...prev, [provider]: data }))
    } catch (err) { console.error(err) }
  }

  const handleModelChange = async (provider, model) => {
    setBusy(provider)
    try {
      await setProviderModel(provider, model)
      setModels((prev) => ({ ...prev, [provider]: { ...prev[provider], current: model } }))
      await load()
    } catch (err) {
      setError(err.message || `Could not set model for ${provider}`)
    } finally { setBusy('') }
  }

  if (!data) {
    return error ? (
      <Callout tone="crit" icon={AlertTriangle}>{error}</Callout>
    ) : (
      <SkeletonRegion label="Loading providers">
        <Card className="p-5 space-y-4">
          <Skeleton className="h-4 w-48" />
          {Array.from({ length: 5 }).map((_, i) => (
            <div key={i} className="flex items-center justify-between gap-4">
              <Skeleton className="h-3 w-28" />
              <Skeleton className="h-6 w-10 rounded-full" />
            </div>
          ))}
        </Card>
      </SkeletonRegion>
    )
  }

  const enabledCount = data.providers.filter((p) => p.enabled && p.has_credentials).length

  return (
    <>
      {error && <Callout tone="crit" icon={AlertTriangle} role="alert">{error}</Callout>}

      <Card className="px-5 py-4 flex items-start sm:items-center justify-between gap-4">
        <div className="flex items-start gap-3 min-w-0">
          <Database className="w-4 h-4 text-ink-subtle mt-0.5 flex-shrink-0" aria-hidden="true" />
          <div className="min-w-0">
            <p id="rag-label" className="text-sm font-medium">Retrieval</p>
            <p className="text-[13px] text-ink-muted mt-0.5">
              {rag?.rag_enabled
                ? `On: answers are grounded in ${rag?.documents ?? 0} indexed chunks.`
                : 'Off: answers use only the model’s own knowledge (the no-RAG baseline).'}
            </p>
          </div>
        </div>
        <Toggle label="Retrieval" on={!!rag?.rag_enabled} busy={busy === 'rag'} onChange={handleRagToggle} />
      </Card>

      <Card>
        <CardHeader
          title="Providers"
          description="Enabled cloud providers each read a share of the retrieved documents in parallel. Ollama is used only when every cloud provider is unreachable."
          actions={<Badge tone={enabledCount ? 'accent' : 'neutral'}>{enabledCount} active</Badge>}
        />
        <ul className="border-t border-line divide-y divide-line">
          {data.providers.map((p) => {
            const Icon = p.local ? HardDrive : Cloud
            const current = models[p.provider]?.current ?? p.model
            return (
              <li key={p.provider} className="px-5 py-4">
                <div className="flex items-start justify-between gap-4">
                  <div className="flex items-start gap-3 min-w-0">
                    <Icon className="w-4 h-4 text-ink-subtle mt-0.5 flex-shrink-0" aria-hidden="true" />
                    <div className="min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="text-sm font-medium">{PROVIDER_LABELS[p.provider] || p.provider}</span>
                        {p.has_credentials ? <Badge tone="ok">Ready</Badge> : <Badge>{p.local ? 'Not running' : 'No key'}</Badge>}
                        {p.model_count > 0 && <span className="text-xs text-ink-subtle tabular">{p.model_count} models</span>}
                      </div>
                      <p className="text-[13px] text-ink-muted mt-0.5">{PROVIDER_NOTES[p.provider]}</p>
                    </div>
                  </div>
                  <Toggle
                    label={`Use ${PROVIDER_LABELS[p.provider] || p.provider}`}
                    on={p.enabled}
                    busy={busy === p.provider}
                    disabled={!p.has_credentials}
                    onChange={(next) => handleToggle(p.provider, next)}
                  />
                </div>

                {p.enabled && p.has_credentials && !p.local && (
                  <div className="mt-3 pl-7">
                    <Select
                      aria-label={`${PROVIDER_LABELS[p.provider]} model`}
                      className="max-w-md font-mono"
                      value={current}
                      onFocus={() => loadModels(p.provider)}
                      onMouseDown={() => loadModels(p.provider)}
                      onChange={(e) => handleModelChange(p.provider, e.target.value)}
                      disabled={busy === p.provider}
                    >
                      <option value={current}>{current}</option>
                      {(models[p.provider]?.models || [])
                        .filter((m) => m !== current)
                        .map((m) => <option key={m} value={m}>{m}</option>)}
                    </Select>
                  </div>
                )}
              </li>
            )
          })}
        </ul>
      </Card>
    </>
  )
}
