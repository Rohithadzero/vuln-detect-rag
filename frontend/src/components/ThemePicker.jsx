import { Check } from 'lucide-react'
import { useTheme } from '../context/ThemeContext'
import { cx } from './ui'

// A miniature of each mode drawn with fixed colours, since the live tokens
// only ever describe the active theme.
const PREVIEW = {
  light: { bg: '#f6f7f9', panel: '#ffffff', line: '#e2e4ea', ink: '#2b2f3a' },
  dark: { bg: '#1b1d23', panel: '#23262e', line: '#343844', ink: '#e9eaee' },
}

function Mini({ mode }) {
  const p = PREVIEW[mode]
  return (
    <div className="h-16 rounded-md overflow-hidden border border-line flex" style={{ background: p.bg }} aria-hidden="true">
      <div className="w-1/4 h-full" style={{ borderRight: `1px solid ${p.line}` }} />
      <div className="flex-1 p-2 space-y-1.5">
        <div className="h-1.5 w-1/2 rounded-full" style={{ background: p.ink, opacity: 0.8 }} />
        <div className="h-6 rounded" style={{ background: p.panel, border: `1px solid ${p.line}` }} />
      </div>
    </div>
  )
}

export default function ThemePicker() {
  const { theme, setTheme, themes } = useTheme()

  return (
    <div role="radiogroup" aria-label="Color theme" className="grid grid-cols-1 sm:grid-cols-3 gap-3">
      {themes.map((t) => {
        const active = t.id === theme
        return (
          <button
            key={t.id}
            type="button"
            role="radio"
            aria-checked={active}
            onClick={() => setTheme(t.id)}
            className={cx(
              'text-left p-2.5 rounded-card border transition-colors duration-150',
              active ? 'border-accent bg-accent-soft/50' : 'border-line hover:border-line-strong bg-surface'
            )}
          >
            {t.id === 'system' ? (
              <div className="h-16 rounded-md overflow-hidden border border-line grid grid-cols-2" aria-hidden="true">
                <div style={{ background: PREVIEW.light.bg }} />
                <div style={{ background: PREVIEW.dark.bg }} />
              </div>
            ) : (
              <Mini mode={t.id} />
            )}
            <div className="flex items-center justify-between mt-2 px-0.5">
              <span className="text-[13px] font-medium">{t.label}</span>
              {active && <Check className="w-4 h-4 text-accent" aria-hidden="true" />}
            </div>
          </button>
        )
      })}
    </div>
  )
}
