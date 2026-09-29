import { useEffect, useState } from 'react'
import { Outlet, useLocation } from 'react-router-dom'
import { Menu, ShieldCheck } from 'lucide-react'
import Sidebar from './Sidebar'
import { IconButton } from './ui'

export default function Layout() {
  const [navOpen, setNavOpen] = useState(false)
  const location = useLocation()

  useEffect(() => { setNavOpen(false) }, [location.pathname])

  useEffect(() => {
    if (!navOpen) return
    const onKey = (e) => { if (e.key === 'Escape') setNavOpen(false) }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [navOpen])

  return (
    <div className="flex h-screen overflow-hidden bg-canvas">
      {/* Desktop: permanent rail. */}
      <div className="hidden lg:flex">
        <Sidebar />
      </div>

      {/* Mobile: drawer over a scrim. */}
      {navOpen && (
        <div className="lg:hidden fixed inset-0 z-40">
          <button
            type="button"
            aria-label="Close navigation"
            className="absolute inset-0 bg-ink/30"
            onClick={() => setNavOpen(false)}
          />
          <div className="absolute inset-y-0 left-0 shadow-pop">
            <Sidebar onNavigate={() => setNavOpen(false)} />
          </div>
        </div>
      )}

      <div className="flex-1 flex flex-col min-w-0">
        <header className="lg:hidden flex items-center gap-2 h-14 px-3 border-b border-line bg-surface">
          <IconButton label="Open navigation" icon={Menu} onClick={() => setNavOpen(true)} aria-expanded={navOpen} />
          <ShieldCheck className="w-5 h-5 text-accent" aria-hidden="true" />
          <span className="font-semibold text-sm">VulnDetect</span>
        </header>
        <main className="flex-1 overflow-auto">
          <div className="max-w-[1280px] mx-auto px-4 sm:px-6 lg:px-8 py-6 lg:py-8 min-h-full flex flex-col">
            <Outlet />
          </div>
        </main>
      </div>
    </div>
  )
}
