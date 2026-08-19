import { lazy, Suspense } from 'react'
import { BrowserRouter, Routes, Route } from 'react-router-dom'
import Layout from './components/Layout'

const Dashboard = lazy(() => import('./pages/Dashboard'))
const ScanConsole = lazy(() => import('./pages/ScanConsole'))
const RAGAssistant = lazy(() => import('./pages/RAGAssistant'))
const CVEDetail = lazy(() => import('./pages/CVEDetail'))
const CVEBrowse = lazy(() => import('./pages/CVEBrowse'))
const KnowledgeGraph = lazy(() => import('./pages/KnowledgeGraph'))
const Settings = lazy(() => import('./pages/Settings'))

function Loading() {
  return (
    <div className="flex items-center justify-center h-full">
      <div className="w-8 h-8 border-4 border-black border-t-neo-cyan bg-white animate-spin" />
    </div>
  )
}

function NotFound() {
  return (
    <div className="flex flex-col items-center justify-center h-full">
      <h1 className="text-8xl font-black mb-4">404</h1>
      <p className="text-lg font-bold uppercase tracking-wider">Page not found</p>
      <a href="/" className="mt-6 px-6 py-3 bg-neo-yellow nb-btn text-sm">
        Go to Dashboard
      </a>
    </div>
  )
}

export default function App() {
  return (
    <BrowserRouter>
      <Suspense fallback={<Loading />}>
        <Routes>
          <Route path="/" element={<Layout />}>
            <Route index element={<Dashboard />} />
            <Route path="scans" element={<ScanConsole />} />
            <Route path="rag" element={<RAGAssistant />} />
            <Route path="cve" element={<CVEBrowse />} />
            <Route path="cve/:cveId" element={<CVEDetail />} />
            <Route path="graph" element={<KnowledgeGraph />} />
            <Route path="settings" element={<Settings />} />
            <Route path="*" element={<NotFound />} />
          </Route>
        </Routes>
      </Suspense>
    </BrowserRouter>
  )
}
