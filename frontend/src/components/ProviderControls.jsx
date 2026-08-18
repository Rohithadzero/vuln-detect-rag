import { useState, useEffect } from 'react'
import { Cloud, HardDrive, Database, Loader2, AlertTriangle, Check, X } from 'lucide-react'
import {
  getProviders, toggleProvider, getProviderModels, setProviderModel,
  getRagConfig, setRagConfig,
} from '../api/client'

const PROVIDER_LABELS = {
  groq: 'Groq',
  gemini: 'Google Gemini',
  openrouter: 'OpenRouter',
  nvidia: 'NVIDIA NIM',
  ollama: 'Ollama (local)',
}

const PROVIDER_NOTES = {
  groq: 'Free tier, fastest responses',
  gemini: 'Free tier, large context',
  openrouter: 'Free models only — paid models are refused',
  nvidia: 'Free tier, widest model catalogue',
  ollama: 'Runs offline; nothing leaves this machine',
}

/**
 * Research controls: enable or disable each LLM backend, pick a model, and
 * turn retrieval on or off.
 *
 * Comparing backends is only meaningful if the others can be switched off, and
 * the contribution of the knowledge base can only be shown by measuring the
 * same questions with retrieval disabled.
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
      setModels((prev) => ({
        ...prev,
        [provider]: { ...prev[provider], current: model },
      }))
      await load()
    } catch (err) {
      setError(err.message || `Could not set model for ${provider}`)
    } finally { setBusy('') }
  }

  if (!data) {
    return (
      <div className="bg-white border-3 border-black p-6 shadow-neb flex items-center gap-3">
        <Loader2 className="w-5 h-5 animate-spin" />
        <span className="font-bold uppercase text-sm">Loading providers</span>
      </div>
    )
  }

  const enabledCount = data.providers.filter((p) => p.enabled && p.has_credentials).length

  return (
    <div className="space-y-4">
      {error && (
        <div className="bg-neo-red text-white border-3 border-black p-3 flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 flex-shrink-0" />
          <span className="text-xs font-bold">{error}</span>
        </div>
      )}

      {/* Retrieval toggle */}
      <div className="bg-white border-3 border-black p-4 shadow-neb">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="flex items-start gap-3 min-w-0">
            <Database className="w-5 h-5 flex-shrink-0 mt-0.5" />
            <div className="min-w-0">
              <h3 className="text-sm font-black uppercase">Retrieval (RAG)</h3>
              <p className="text-xs font-bold text-gray-600 mt-0.5">
                {rag?.rag_enabled
                  ? `On — answers grounded in ${rag?.documents ?? 0} indexed chunks`
                  : 'Off — answers come from the model’s own knowledge only (no-RAG baseline)'}
              </p>
            </div>
          </div>
          <Toggle
            on={!!rag?.rag_enabled}
            busy={busy === 'rag'}
            onChange={(next) => handleRagToggle(next)}
          />
        </div>
      </div>

      {/* Provider toggles */}
      <div className="bg-white border-3 border-black shadow-neb">
        <div className="p-4 border-b-[3px] border-black bg-neo-cyan flex items-center justify-between gap-3">
          <h3 className="text-sm font-black uppercase">LLM Providers</h3>
          <span className="text-[10px] font-black uppercase">
            {enabledCount} active
            {data.ensemble_enabled && enabledCount > 1 ? ` · ${data.ensemble_mode}` : ''}
          </span>
        </div>

        <div className="divide-y-[2px] divide-black">
          {data.providers.map((p) => (
            <div key={p.provider} className="p-4">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                <div className="flex items-start gap-3 min-w-0">
                  {p.local
                    ? <HardDrive className="w-4 h-4 flex-shrink-0 mt-1" />
                    : <Cloud className="w-4 h-4 flex-shrink-0 mt-1" />}
                  <div className="min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-sm font-black uppercase">
                        {PROVIDER_LABELS[p.provider] || p.provider}
                      </span>
                      {p.has_credentials ? (
                        <span className="text-[9px] font-black uppercase px-1.5 py-0.5 border-2 border-black bg-neo-green flex items-center gap-1">
                          <Check className="w-2.5 h-2.5" /> Ready
                        </span>
                      ) : (
                        <span className="text-[9px] font-black uppercase px-1.5 py-0.5 border-2 border-black bg-gray-200 flex items-center gap-1">
                          <X className="w-2.5 h-2.5" /> No key
                        </span>
                      )}
                      {p.model_count > 0 && (
                        <span className="text-[9px] font-bold text-gray-500">
                          {p.model_count} models
                        </span>
                      )}
                    </div>
                    <p className="text-[11px] font-bold text-gray-600 mt-0.5">
                      {PROVIDER_NOTES[p.provider]}
                    </p>
                    {p.error && (
                      <p className="text-[11px] font-bold text-neo-red mt-0.5 break-words">
                        {p.error}
                      </p>
                    )}
                  </div>
                </div>

                <Toggle
                  on={p.enabled}
                  busy={busy === p.provider}
                  disabled={!p.has_credentials}
                  onChange={(next) => handleToggle(p.provider, next)}
                />
              </div>

              {p.enabled && p.has_credentials && !p.local && (
                <div className="mt-3 pl-7">
                  <select
                    className="w-full max-w-md bg-white border-2 border-black px-2 py-1.5 text-xs font-mono nb-input"
                    value={models[p.provider]?.current ?? p.model}
                    onFocus={() => loadModels(p.provider)}
                    onChange={(e) => handleModelChange(p.provider, e.target.value)}
                    disabled={busy === p.provider}
                  >
                    <option value={models[p.provider]?.current ?? p.model}>
                      {models[p.provider]?.current ?? p.model}
                    </option>
                    {(models[p.provider]?.models || [])
                      .filter((m) => m !== (models[p.provider]?.current ?? p.model))
                      .map((m) => <option key={m} value={m}>{m}</option>)}
                  </select>
                </div>
              )}
            </div>
          ))}
        </div>
      </div>

      <p className="text-[10px] font-bold text-gray-500 uppercase">
        Enabled cloud providers are queried in parallel and their answers reconciled.
        Ollama is used only when every cloud provider is unreachable.
      </p>
    </div>
  )
}

function Toggle({ on, onChange, busy, disabled }) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={on}
      disabled={busy || disabled}
      onClick={() => onChange(!on)}
      className={`relative w-16 h-8 border-3 border-black flex-shrink-0 transition-colors disabled:opacity-40 ${
        on ? 'bg-neo-green' : 'bg-gray-200'
      }`}
    >
      <span
        className={`absolute top-0.5 w-6 h-6 bg-white border-2 border-black transition-all ${
          on ? 'left-[calc(100%-1.75rem)]' : 'left-0.5'
        }`}
      >
        {busy && <Loader2 className="w-3 h-3 animate-spin m-auto mt-0.5" />}
      </span>
    </button>
  )
}
