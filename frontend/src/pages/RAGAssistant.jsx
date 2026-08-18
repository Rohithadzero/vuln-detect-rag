import { useState, useEffect } from 'react'
import { Bot, RefreshCw, Database, MessageSquare, Trash2, Cpu, AlertTriangle } from 'lucide-react'
import { chatRAG, getChatHistory, listSessions, deleteSession, getCVEStats, getLLMStatus } from '../api/client'
import ChatPanel from '../components/ChatPanel'

export default function RAGAssistant() {
  const [messages, setMessages] = useState([])
  const [loading, setLoading] = useState(false)
  const [sessionId, setSessionId] = useState(`session_${Date.now()}`)
  const [sessions, setSessions] = useState([])
  const [cveCount, setCveCount] = useState(0)
  const [llmStatus, setLlmStatus] = useState(null)

  useEffect(() => {
    loadSessions()
    loadCVECount()
    loadLLMStatus()
  }, [])

  const loadLLMStatus = async () => {
    try {
      const { data } = await getLLMStatus()
      setLlmStatus(data)
    } catch (err) {
      console.error(err)
      setLlmStatus({ available: false, model: '', provider: 'ollama', models: [] })
    }
  }

  const loadCVECount = async () => {
    try {
      const { data } = await getCVEStats()
      const total = Object.values(data).reduce((sum, count) => sum + count, 0)
      setCveCount(total)
    } catch (err) { console.error(err) }
  }

  const loadSessions = async () => {
    try { const { data } = await listSessions(); setSessions(data) } catch (err) { console.error(err) }
  }

  const loadSession = async (sid) => {
    setSessionId(sid)
    try {
      const { data } = await getChatHistory(sid)
      setMessages(data.map(m => ({ role: m.role, content: m.content, sources: m.sources || [] })))
    } catch (err) { console.error(err) }
  }

  const handleSend = async (message) => {
    setMessages((prev) => [...prev, { role: 'user', content: message }])
    setLoading(true)
    try {
      const { data } = await chatRAG(message, sessionId)
      setMessages((prev) => [...prev, { role: 'assistant', content: data.answer, sources: data.sources }])
      loadSessions()
    } catch (err) {
      setMessages((prev) => [...prev, {
        role: 'assistant',
        content: 'Error processing your request. Ensure the backend is running.',
        sources: [],
      }])
    } finally { setLoading(false) }
  }

  const clearChat = () => { setMessages([]); setSessionId(`session_${Date.now()}`) }

  const handleDeleteSession = async (sid) => {
    try {
      await deleteSession(sid)
      if (sid === sessionId) clearChat()
      loadSessions()
    } catch (err) { console.error(err) }
  }

  return (
    <div className="h-full flex flex-col min-w-0">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-4">
        <div className="min-w-0">
          <h1 className="text-3xl font-black uppercase tracking-tight">RAG Assistant</h1>
          <p className="text-sm font-bold text-gray-600 mt-1 uppercase tracking-wider">AI-powered vulnerability intelligence</p>
        </div>
        <button onClick={clearChat} className="px-4 py-2 bg-neo-yellow border-3 border-black text-sm font-bold nb-btn flex items-center gap-2 flex-shrink-0">
          <RefreshCw className="w-4 h-4" /> New Chat
        </button>
      </div>

      {/* LLM Status Banner */}
      {llmStatus && (
        <div className={`mb-4 px-4 py-3 border-3 border-black flex items-center gap-3 ${
          llmStatus.available ? 'bg-neo-green' : 'bg-neo-red text-white'
        }`}>
          {llmStatus.available ? (
            <>
              <Cpu className="w-5 h-5 flex-shrink-0" />
              <div className="min-w-0">
                <span className="font-black uppercase text-sm">Local LLM Active: </span>
                <span className="font-mono text-sm font-bold">{llmStatus.model}</span>
                <span className="text-xs ml-2 font-bold">via Ollama</span>
              </div>
            </>
          ) : (
            <>
              <AlertTriangle className="w-5 h-5 flex-shrink-0" />
              <div className="min-w-0">
                <span className="font-black uppercase text-sm">Local LLM Not Found</span>
                <span className="text-xs block font-bold">
                  Install Ollama: <code className="bg-black/20 px-1.5 py-0.5 text-[10px] font-mono">ollama pull qwen2.5-coder:7b</code>
                </span>
              </div>
            </>
          )}
        </div>
      )}

      <div className="flex gap-4 flex-1 min-h-0">
        {/* Session History Sidebar */}
        {sessions.length > 0 && (
          <div className="hidden lg:flex w-56 flex-shrink-0 bg-white border-3 border-black shadow-neb-sm flex-col overflow-hidden">
            <div className="p-3 border-b-[3px] border-black bg-neo-purple">
              <h3 className="text-[10px] font-black uppercase">Sessions</h3>
            </div>
            <div className="flex-1 overflow-auto divide-y-[2px] divide-black">
              {sessions.map((s) => (
                <div
                  key={s.session_id}
                  className={`px-3 py-2 flex items-center justify-between cursor-pointer hover:bg-gray-50 transition-colors ${
                    s.session_id === sessionId ? 'bg-neo-cyan/20' : ''
                  }`}
                  onClick={() => loadSession(s.session_id)}
                >
                  <div className="flex items-center gap-2 min-w-0">
                    <MessageSquare className="w-3 h-3 flex-shrink-0" />
                    <span className="text-xs font-bold truncate">{s.message_count} messages</span>
                  </div>
                  <button
                    onClick={(e) => { e.stopPropagation(); handleDeleteSession(s.session_id) }}
                    className="hover:text-neo-red flex-shrink-0"
                  >
                    <Trash2 className="w-3 h-3" />
                  </button>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Chat Panel */}
        <div className="flex-1 bg-white border-3 border-black shadow-neb overflow-hidden">
          <ChatPanel messages={messages} onSend={handleSend} loading={loading} />
        </div>
      </div>

      {/* Info footer */}
      <div className="mt-3 flex items-center gap-4 text-[10px] font-bold text-gray-500 uppercase">
        <div className="flex items-center gap-1">
          <Database className="w-3 h-3" />
          <span>{cveCount} CVEs indexed</span>
        </div>
        <div className="flex items-center gap-1">
          <Cpu className="w-3 h-3" />
          <span>
            {llmStatus?.available ? `ChromaDB + ${llmStatus.model} (Ollama)` : 'ChromaDB (no LLM — fallback mode)'}
          </span>
        </div>
      </div>
    </div>
  )
}
