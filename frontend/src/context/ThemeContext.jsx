import { createContext, useContext, useEffect, useMemo, useState } from 'react'

const THEME_STORAGE_KEY = 'vulndetect-theme'

/**
 * The available themes, as data rather than as scattered conditionals.
 *
 * Everything that renders a theme picker reads this list, so adding a theme is
 * a matter of appending one entry here and one `.theme-<id>` block in
 * index.css -- not of editing the sidebar, the settings page and the layout
 * separately and hoping they agree.
 *
 * `swatch` drives the little preview tiles in the picker. They are ordinary
 * colours rather than a rendered miniature of the UI: a three-colour chip
 * conveys the palette honestly and cannot drift out of sync with the real
 * styling the way a hand-built mock preview would.
 */
export const THEMES = [
  {
    id: 'classic',
    label: 'Classic',
    tagline: 'Neo-brutalist',
    description:
      'Hard black borders, square corners and offset shadows. High contrast and deliberately loud.',
    swatch: ['#fde047', '#22d3ee', '#000000'],
  },
  {
    id: 'color',
    label: 'Color',
    tagline: 'Neo-brutalist, softened',
    description:
      'The same structure in violet, with rounded corners and lighter shadows.',
    swatch: ['#3a03f5', '#a855f7', '#f5f0ff'],
  },
  {
    id: 'standard',
    label: 'Standard',
    tagline: 'Conventional',
    description:
      'An ordinary application look: thin grey borders, soft shadows, a blue accent. The safe choice for a demo or a screenshot.',
    swatch: ['#2563eb', '#e2e8f0', '#ffffff'],
  },
  {
    id: 'minimal',
    label: 'Minimal',
    tagline: 'Quiet',
    description:
      'No shadows, hairline dividers, muted type. Puts the data first and the chrome last.',
    swatch: ['#18181b', '#d4d4d8', '#fafafa'],
  },
  {
    id: 'neumorph',
    label: 'Neumorphic',
    tagline: 'Soft UI',
    description:
      'Borderless surfaces raised and recessed with paired light and dark shadows on a single background tone.',
    swatch: ['#e0e5ec', '#a3b1c6', '#ffffff'],
  },
  {
    id: 'midnight',
    label: 'Midnight',
    tagline: 'Dark',
    description:
      'A dark surface palette with a cyan accent, for long sessions and low light.',
    swatch: ['#0f172a', '#22d3ee', '#1e293b'],
  },
]

export const THEME_IDS = THEMES.map((t) => t.id)
const DEFAULT_THEME = 'classic'

const ThemeContext = createContext(null)

export function ThemeProvider({ children }) {
  const [theme, setThemeState] = useState(() => {
    if (typeof window === 'undefined') return DEFAULT_THEME
    const saved = window.localStorage.getItem(THEME_STORAGE_KEY)
    return THEME_IDS.includes(saved) ? saved : DEFAULT_THEME
  })

  // An unknown id would leave the app with no theme class at all and a
  // half-styled shell, so it is coerced rather than trusted -- localStorage
  // survives across versions, and a theme removed in a later release would
  // otherwise strand anyone who had it selected.
  const setTheme = (next) =>
    setThemeState(THEME_IDS.includes(next) ? next : DEFAULT_THEME)

  useEffect(() => {
    document.body.dataset.theme = theme
    window.localStorage.setItem(THEME_STORAGE_KEY, theme)
  }, [theme])

  const value = useMemo(
    () => ({ theme, setTheme, themes: THEMES }),
    [theme]
  )

  return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>
}

export function useTheme() {
  const context = useContext(ThemeContext)
  if (!context) throw new Error('useTheme must be used within ThemeProvider')
  return context
}
