import { Outlet } from 'react-router-dom'
import Sidebar from './Sidebar'
import { useTheme } from '../context/ThemeContext'

export default function Layout() {
  const { theme } = useTheme()

  return (
    <div className={`flex h-screen overflow-hidden app-shell ${theme === 'color' ? 'theme-color' : ''}`}>
      <Sidebar />
      <main className="flex-1 overflow-auto overflow-x-hidden p-4 sm:p-6 lg:p-8 min-w-0">
        <Outlet />
      </main>
    </div>
  )
}
