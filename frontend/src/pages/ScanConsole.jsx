import { useState, useEffect, useRef } from 'react'
import { useSearchParams } from 'react-router-dom'
import { History, RefreshCw, Star, StarOff } from 'lucide-react'
import { startScan, getScanResults, getAttackPaths, listScans, getFavorites, addFavorite, deleteFavorite } from '../api/client'
import ScanForm from '../components/ScanForm'
import ScanResults from '../components/ScanResults'
import AttackPathGraph from '../components/AttackPathGraph'

export default function ScanConsole() {
  const [searchParams] = useSearchParams()
  const [scanning, setScanning] = useState(false)
  const [currentScan, setCurrentScan] = useState(null)
  const [vulnerabilities, setVulnerabilities] = useState([])
  const [attackPaths, setAttackPaths] = useState([])
  const [scanHistory, setScanHistory] = useState([])
  const [favorites, setFavorites] = useState([])
  const [activeTab, setActiveTab] = useState('results')
  const pollRef = useRef(null)

  useEffect(() => {
    loadHistory()
    loadFavorites()
    const scanId = searchParams.get('scan')
    if (scanId) loadScan(parseInt(scanId))
    return () => { if (pollRef.current) clearInterval(pollRef.current) }
  }, [])

  const loadHistory = async () => {
    try { const { data } = await listScans(); setScanHistory(data) } catch (err) { console.error(err) }
  }

  const loadFavorites = async () => {
    try { const { data } = await getFavorites(); setFavorites(data) } catch (err) { console.error(err) }
  }

  const loadScan = async (scanId) => {
    try {
      if (pollRef.current) {
        clearInterval(pollRef.current)
        pollRef.current = null
      }
      const { data } = await getScanResults(scanId)
      setCurrentScan(data.scan)
      setVulnerabilities(data.vulnerabilities)
      if (data.scan.status === 'pending' || data.scan.status === 'running') {
        setScanning(true)
        pollScan(scanId)
      } else {
        setScanning(false)
        if (data.scan.status === 'completed') {
          loadAttackPaths(scanId)
        }
      }
    } catch (err) { console.error(err) }
  }

  const loadAttackPaths = async (scanId) => {
    try { const { data } = await getAttackPaths(scanId); setAttackPaths(data.paths || []) } catch (err) { console.error(err) }
  }

  const handleStartScan = async (target, scanners) => {
    setScanning(true)
    setVulnerabilities([])
    setAttackPaths([])
    try {
      const { data } = await startScan(target, scanners)
      setCurrentScan(data)
      pollScan(data.id)
    } catch (err) { console.error(err); setScanning(false) }
  }

  const handleAddFavorite = async (target) => {
    try { await addFavorite(target, ''); loadFavorites() } catch (err) { console.error(err) }
  }

  const handleDeleteFavorite = async (id) => {
    try { await deleteFavorite(id); loadFavorites() } catch (err) { console.error(err) }
  }

  const pollScan = (scanId) => {
    if (pollRef.current) clearInterval(pollRef.current)
    pollRef.current = setInterval(async () => {
      try {
        const { data } = await getScanResults(scanId)
        setCurrentScan(data.scan)
        setVulnerabilities(data.vulnerabilities)
        loadHistory()
        if (data.scan.status === 'completed' || data.scan.status === 'failed') {
          clearInterval(pollRef.current)
          pollRef.current = null
          setScanning(false)
          if (data.scan.status === 'completed') loadAttackPaths(scanId)
        }
      } catch (err) {
        clearInterval(pollRef.current)
        pollRef.current = null
        setScanning(false)
      }
    }, 2000)
  }

  return (
    <div className="space-y-6 min-w-0">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div className="min-w-0">
          <h1 className="text-3xl font-black uppercase tracking-tight">Scan Console</h1>
          <p className="text-sm font-bold text-gray-600 mt-1 uppercase tracking-wider">Launch and monitor vulnerability scans</p>
        </div>
        <button onClick={loadHistory} className="px-4 py-2 bg-white border-3 border-black text-sm font-bold nb-btn shadow-neb flex items-center gap-2 flex-shrink-0">
          <RefreshCw className="w-4 h-4" /> Refresh
        </button>
      </div>

      <div className="flex flex-col lg:grid lg:grid-cols-3 gap-6">
        {/* Left column */}
        <div className="lg:col-span-1 space-y-4">
          <div className="bg-white border-3 border-black p-5 shadow-neb">
            <h3 className="text-sm font-black uppercase tracking-wider mb-4">New Scan</h3>
            <ScanForm onStartScan={handleStartScan} loading={scanning} onAddFavorite={handleAddFavorite} />
          </div>

          {/* Favorites */}
          {favorites.length > 0 && (
            <div className="bg-white border-3 border-black shadow-neb overflow-hidden">
              <div className="p-3 border-b-[3px] border-black bg-neo-yellow flex items-center gap-2">
                <Star className="w-4 h-4" />
                <h3 className="text-xs font-black uppercase">Favorites</h3>
              </div>
              <div className="divide-y-[2px] divide-black">
                {favorites.map((fav) => (
                  <div key={fav.id} className="px-4 py-3 flex items-center justify-between hover:bg-gray-50 min-h-[44px]">
                    <span className="text-sm font-bold font-mono">{fav.target}</span>
                    <button onClick={() => handleDeleteFavorite(fav.id)} className="hover:text-neo-red p-2" aria-label={`Remove ${fav.target} from favorites`}>
                      <StarOff className="w-4 h-4" />
                    </button>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Scan History */}
          <div className="bg-white border-3 border-black shadow-neb overflow-hidden">
            <div className="p-3 border-b-[3px] border-black bg-neo-purple flex items-center gap-2">
              <History className="w-4 h-4" />
              <h3 className="text-xs font-black uppercase">Scan History</h3>
            </div>
            <div className="divide-y-[2px] divide-black max-h-[400px] overflow-auto">
              {scanHistory.map((scan) => (
                <button
                  key={scan.id}
                  onClick={() => { loadScan(scan.id); setActiveTab('results') }}
                  className={`w-full px-4 py-4 cursor-pointer hover:bg-gray-50 transition-colors text-left ${
                    currentScan?.id === scan.id ? 'bg-neo-cyan/30 border-l-[4px] border-black' : ''
                  }`}
                  aria-label={`Load scan for ${scan.target}`}
                >
                  <div className="text-sm font-bold font-mono">{scan.target}</div>
                  <div className="flex items-center gap-2 mt-1">
                    <span className={`text-[10px] px-1.5 py-0.5 border-2 border-black font-black uppercase ${
                      scan.status === 'completed' ? 'bg-neo-green' : scan.status === 'failed' ? 'bg-neo-red text-white' : 'bg-neo-yellow'
                    }`}>
                      {scan.status}
                    </span>
                    <span className="text-[10px] font-bold">{scan.total_vulnerabilities} vulns</span>
                    {scan.progress > 0 && scan.progress < 100 && (
                      <span className="text-[10px] font-bold text-blue-600">{scan.progress}%</span>
                    )}
                  </div>
                </button>
              ))}
              {scanHistory.length === 0 && (
                <div className="p-4 text-center text-gray-400 text-sm font-bold uppercase">No scans yet</div>
              )}
            </div>
          </div>
        </div>

        {/* Right column */}
        <div className="lg:col-span-2">
          {currentScan ? (
            <div className="space-y-4">
              <div className="flex gap-1 bg-white border-3 border-black p-1 shadow-neb-sm">
                {['results', 'attack-paths'].map((tab) => (
                  <button
                    key={tab}
                    onClick={() => setActiveTab(tab)}
                    className={`flex-1 px-4 py-2 text-sm font-black uppercase tracking-wide transition-colors border-2 border-transparent ${
                      activeTab === tab ? 'bg-neo-cyan border-black' : 'hover:bg-gray-100'
                    }`}
                  >
                    {tab === 'results' ? 'Vulnerabilities' : 'Attack Paths'}
                  </button>
                ))}
              </div>
              {activeTab === 'results' && <ScanResults scan={currentScan} vulnerabilities={vulnerabilities} />}
              {activeTab === 'attack-paths' && <AttackPathGraph paths={attackPaths} />}
            </div>
          ) : (
            <div className="bg-white border-3 border-black p-12 text-center shadow-neb">
              <p className="text-xl font-black uppercase">No scan selected</p>
              <p className="text-sm font-bold text-gray-500 mt-2 uppercase">Start a new scan or select one from history</p>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
