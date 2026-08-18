import { useState, useRef, useEffect } from 'react'
import { Send, Bot, User, Loader2, ExternalLink } from 'lucide-react'

export default function ChatPanel({ messages, onSend, loading }) {
  const [input, setInput] = useState('')
  const messagesEndRef = useRef(null)

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages])

  const handleSubmit = (e) => {
    e.preventDefault()
    if (!input.trim() || loading) return
    onSend(input.trim())
    setInput('')
  }

  return (
    <div className="flex flex-col h-full">
      <div className="flex-1 overflow-auto p-4 space-y-4">
        {messages.length === 0 && (
          <div className="flex flex-col items-center justify-center h-full text-gray-400">
            <Bot className="w-12 h-12 mb-3" />
            <h3 className="text-lg font-black uppercase">Vulnerability Assistant</h3>
            <p className="text-sm mt-1 font-bold">Ask about CVEs, remediation, or exploits</p>
            <div className="mt-4 space-y-2 text-sm">
              <p className="font-bold text-gray-500 uppercase text-[10px]">Try asking:</p>
              <div className="flex flex-wrap gap-2 mt-2">
                {[
                  'What is CVE-2021-44228?',
                  'How to remediate Log4Shell?',
                  'List critical CVEs for Exchange',
                  'Attack vectors for Spring4Shell?',
                ].map((q) => (
                  <button
                    key={q}
                    onClick={() => onSend(q)}
                    className="px-3 py-1.5 bg-white border-3 border-black text-xs font-bold shadow-[3px_3px_0px_0px_#000] hover:shadow-[1px_1px_0px_0px_#000] hover:translate-x-[-2px] hover:translate-y-[-2px] transition-all"
                  >
                    {q}
                  </button>
                ))}
              </div>
            </div>
          </div>
        )}

        {messages.map((msg, i) => (
          <div key={i} className={`flex gap-3 ${msg.role === 'user' ? 'justify-end' : ''}`}>
            {msg.role === 'assistant' && (
              <div className="w-8 h-8 bg-neo-purple border-2 border-black flex items-center justify-center flex-shrink-0">
                <Bot className="w-4 h-4" />
              </div>
            )}
            <div className={`max-w-[80%] px-4 py-3 ${msg.role === 'user' ? 'chat-user' : 'chat-assistant'}`}>
              <p className="text-sm whitespace-pre-wrap">{msg.content}</p>
              {msg.sources?.length > 0 && (
                <div className="mt-3 pt-3 border-t-2 border-black/20 space-y-1">
                  <p className="text-[10px] uppercase font-black opacity-60">Sources</p>
                  {msg.sources.map((s, j) => (
                    <div key={j} className="flex items-center gap-2 text-xs font-bold">
                      <ExternalLink className="w-3 h-3" />
                      <span className="font-mono">{s.cve_id || 'CVE'}</span>
                      <span className="opacity-50">({(s.score * 100).toFixed(0)}%)</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
            {msg.role === 'user' && (
              <div className="w-8 h-8 bg-neo-cyan border-2 border-black flex items-center justify-center flex-shrink-0">
                <User className="w-4 h-4" />
              </div>
            )}
          </div>
        ))}

        {loading && (
          <div className="flex gap-3">
            <div className="w-8 h-8 bg-neo-purple border-2 border-black flex items-center justify-center">
              <Bot className="w-4 h-4" />
            </div>
            <div className="bg-gray-200 border-3 border-black px-4 py-3 flex items-center gap-3">
              <Loader2 className="w-4 h-4 animate-spin" />
              <span className="text-sm font-bold">Generating response... (Local LLMs may take 30-60s)</span>
            </div>
          </div>
        )}
        <div ref={messagesEndRef} />
      </div>

      <form onSubmit={handleSubmit} className="p-4 border-t-[3px] border-black bg-white">
        <div className="flex gap-2">
          <input
            type="text"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="Ask about vulnerabilities, CVEs, remediation..."
            className="flex-1 bg-white border-3 border-black px-4 py-2.5 text-sm font-mono placeholder-gray-400 nb-input"
            disabled={loading}
            aria-label="Chat message input"
          />
          <button
            type="submit"
            disabled={loading || !input.trim()}
            className="px-4 py-2.5 bg-neo-cyan border-3 border-black nb-btn disabled:bg-gray-200 disabled:shadow-none"
            aria-label="Send message"
          >
            <Send className="w-4 h-4" aria-hidden="true" />
          </button>
        </div>
      </form>
    </div>
  )
}
