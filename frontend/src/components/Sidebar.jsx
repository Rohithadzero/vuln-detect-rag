import { NavLink } from 'react-router-dom'
import { Shield, LayoutDashboard, Scan, MessageSquare, Activity, Database, Network, Settings } from 'lucide-react'
import { useTheme } from '../context/ThemeContext'

const navItems = [
  { to: '/', icon: LayoutDashboard, label: 'Dashboard', color: 'bg-neo-yellow' },
  { to: '/scans', icon: Scan, label: 'Scan Console', color: 'bg-neo-cyan' },
  { to: '/rag', icon: MessageSquare, label: 'RAG Assistant', color: 'bg-neo-purple' },
  { to: '/cve', icon: Database, label: 'CVE Database', color: 'bg-neo-green' },
  { to: '/graph', icon: Network, label: 'Knowledge Graph', color: 'bg-neo-orange' },
  { to: '/settings', icon: Settings, label: 'Settings', color: 'bg-neo-pink' },
]

export default function Sidebar() {
  const { theme, setTheme, themes } = useTheme()

  return (
    <aside className="w-64 app-sidebar border-r-[3px] border-black flex flex-col z-10">
      <div className="p-5 border-b-[3px] border-black app-sidebar-accent">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 bg-black flex items-center justify-center">
            <Shield className="w-6 h-6 text-neo-yellow" />
          </div>
          <div>
            <h1 className="text-lg font-black uppercase tracking-tight text-black">VulnDetect</h1>
            <p className="text-[10px] font-bold uppercase tracking-widest text-black/60">RAG Platform</p>
          </div>
        </div>
      </div>

      {/* Two hardcoded buttons could not represent six themes, and a row of six
          would crowd the sidebar. A select stays one line however many themes
          exist, and the full picker with descriptions lives in Settings. */}
      <div className="p-4 border-b-[3px] border-black">
        <label
          htmlFor="theme-select"
          className="block text-[10px] font-black uppercase tracking-widest mb-2 text-gray-500"
        >
          Theme
        </label>
        <select
          id="theme-select"
          value={theme}
          onChange={(e) => setTheme(e.target.value)}
          className="w-full px-3 py-2 text-[11px] font-black uppercase bg-white border-3 border-black nb-input cursor-pointer"
        >
          {themes.map((t) => (
            <option key={t.id} value={t.id}>
              {t.label}
            </option>
          ))}
        </select>
      </div>

      <nav className="flex-1 p-4 space-y-2">
        {navItems.map(({ to, icon: Icon, label, color }) => (
          <NavLink
            key={to}
            to={to}
            end={to === '/'}
            aria-label={label}
            className={({ isActive }) =>
              `flex items-center gap-3 px-4 py-3 text-sm font-bold uppercase tracking-wide transition-all border-3 border-black app-nav-link ${
                isActive
                  ? `${color} shadow-[3px_3px_0px_0px_#000] translate-x-[-2px] translate-y-[-1px]`
                  : 'bg-white hover:bg-gray-100 shadow-[4px_4px_0px_0px_#000] hover:shadow-[2px_2px_0px_0px_#000] hover:translate-x-[-2px] hover:translate-y-[-2px]'
              }`
            }
          >
            <Icon className="w-5 h-5" aria-hidden="true" />
            {label}
          </NavLink>
        ))}
      </nav>

      <div className="p-4 border-t-[3px] border-black">
        <div className="flex items-center gap-2 text-xs font-bold text-gray-500 uppercase">
          <Activity className="w-3 h-3" />
          <span>v3.5.0</span>
        </div>
      </div>
    </aside>
  )
}
