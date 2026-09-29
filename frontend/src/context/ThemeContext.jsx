import { createContext, useContext, useEffect, useMemo, useState } from 'react'

const THEME_STORAGE_KEY = 'vulndetect-theme'

export const THEMES = [
  { id: 'light', label: 'Light' },
  { id: 'dark', label: 'Dark' },
  { id: 'system', label: 'System' },
]

const THEME_IDS = THEMES.map((t) => t.id)

// Earlier releases stored ids like "classic" or "midnight". Those are coerced
// to "system" rather than trusted, so an upgrade never strands a user.
function readSaved() {
  try {
    const saved = window.localStorage.getItem(THEME_STORAGE_KEY)
    return THEME_IDS.includes(saved) ? saved : 'system'
  } catch {
    return 'system'
  }
}

const darkQuery = () =>
  typeof window !== 'undefined' && window.matchMedia
    ? window.matchMedia('(prefers-color-scheme: dark)')
    : null

const ThemeContext = createContext(null)

export function ThemeProvider({ children }) {
  const [theme, setThemeState] = useState(readSaved)
  const [systemDark, setSystemDark] = useState(() => !!darkQuery()?.matches)

  useEffect(() => {
    const mq = darkQuery()
    if (!mq) return
    const onChange = (e) => setSystemDark(e.matches)
    mq.addEventListener('change', onChange)
    return () => mq.removeEventListener('change', onChange)
  }, [])

  const resolved = theme === 'system' ? (systemDark ? 'dark' : 'light') : theme

  useEffect(() => {
    document.documentElement.dataset.theme = resolved
  }, [resolved])

  const setTheme = (next) => {
    const value = THEME_IDS.includes(next) ? next : 'system'
    setThemeState(value)
    try {
      window.localStorage.setItem(THEME_STORAGE_KEY, value)
    } catch {
      // Private mode or blocked storage: the choice still applies this session.
    }
  }

  const value = useMemo(
    () => ({ theme, resolved, setTheme, themes: THEMES }),
    [theme, resolved]
  )

  return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>
}

export function useTheme() {
  const context = useContext(ThemeContext)
  if (!context) throw new Error('useTheme must be used within ThemeProvider')
  return context
}
