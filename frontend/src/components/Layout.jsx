import { Outlet } from 'react-router-dom'
import Sidebar from './Sidebar'
import { useTheme } from '../context/ThemeContext'

export default function Layout() {
  const { theme } = useTheme()

  return (
    // The theme class is always applied, not only for the one non-default
    // theme. Special-casing a single id meant every new theme needed the
    // condition edited here as well as its own stylesheet block.
    <div className={`flex h-screen overflow-hidden app-shell theme-${theme}`}>
      <Sidebar />
      <main className="flex-1 overflow-auto overflow-x-hidden p-4 sm:p-6 lg:p-8 min-w-0">
        <Outlet />
      </main>
    </div>
  )
}
