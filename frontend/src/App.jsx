import { lazy, Suspense } from 'react'
import { BrowserRouter, Routes, Route } from 'react-router-dom'
import Layout from './components/Layout'
import Skeleton, { SkeletonRegion, SkeletonStatCards, SkeletonPanel } from './components/Skeleton'

const Dashboard = lazy(() => import('./pages/Dashboard'))
const ScanConsole = lazy(() => import('./pages/ScanConsole'))
const RAGAssistant = lazy(() => import('./pages/RAGAssistant'))
const CVEDetail = lazy(() => import('./pages/CVEDetail'))
const CVEBrowse = lazy(() => import('./pages/CVEBrowse'))
const KnowledgeGraph = lazy(() => import('./pages/KnowledgeGraph'))
const Settings = lazy(() => import('./pages/Settings'))

// Route-level fallback while a lazily imported page chunk downloads. Generic
// on purpose: at this point the router knows which route is coming but the
// module defining its layout has not arrived, so a page header and a couple of
// blocks is the most honest outline available.
function Loading() {
  return (
    <SkeletonRegion label="Loading page" className="space-y-6">
      <div className="space-y-2">
        <Skeleton className="h-8 w-56" />
        <Skeleton className="h-3 w-72" />
      </div>
      <SkeletonStatCards count={4} />
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <SkeletonPanel />
        <SkeletonPanel />
      </div>
    </SkeletonRegion>
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
