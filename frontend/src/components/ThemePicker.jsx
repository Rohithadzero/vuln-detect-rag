import { Check, Palette } from 'lucide-react'
import { useTheme } from '../context/ThemeContext'

/**
 * The theme picker shown on the Settings page.
 *
 * Each option is a real button carrying its own palette swatch, so the choice
 * is made by looking rather than by reading a name. The swatch is three flat
 * colours taken from the theme definition, not a miniature render of the UI:
 * a mock preview would have to be maintained by hand alongside the stylesheet
 * and would eventually describe a theme that no longer looks like that.
 *
 * Selection applies immediately. There is no save button because the whole
 * page repaints in the chosen theme the moment it is clicked, which is a more
 * convincing preview than any thumbnail, and the choice is persisted to
 * localStorage by the provider.
 */
export default function ThemePicker() {
  const { theme, setTheme, themes } = useTheme()

  return (
    <div className="bg-white border-3 border-black p-5 shadow-neb">
      <div className="flex items-center gap-2 mb-1">
        <Palette className="w-5 h-5 flex-shrink-0" />
        <h2 className="text-sm font-black uppercase tracking-wider">Theme</h2>
      </div>
      <p className="text-xs font-bold text-gray-600 mb-4">
        Applies immediately and is remembered on this device.
      </p>

      <div
        className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3"
        role="radiogroup"
        aria-label="Interface theme"
      >
        {themes.map((t) => {
          const active = t.id === theme
          return (
            <button
              key={t.id}
              type="button"
              role="radio"
              aria-checked={active}
              onClick={() => setTheme(t.id)}
              className={`text-left p-3 border-3 border-black transition-all ${
                active
                  ? 'bg-neo-yellow shadow-neb-xs'
                  : 'bg-white shadow-neb-sm hover:shadow-neb-hover'
              }`}
            >
              <div className="flex items-center justify-between gap-2 mb-2">
                <span className="text-xs font-black uppercase tracking-wider">
                  {t.label}
                </span>
                {active && <Check className="w-4 h-4 flex-shrink-0" />}
              </div>

              {/* The swatch is decorative -- the label already names the theme,
                  so announcing three colour chips adds noise for a screen
                  reader and nothing else. */}
              <div className="flex gap-1 mb-2" aria-hidden="true">
                {t.swatch.map((c) => (
                  <span
                    key={c}
                    className="w-7 h-7 border-2 border-black flex-shrink-0"
                    style={{ backgroundColor: c }}
                  />
                ))}
              </div>

              <div className="text-[10px] font-black uppercase tracking-wider text-gray-500">
                {t.tagline}
              </div>
              <p className="text-[11px] font-bold text-gray-600 mt-1 leading-snug">
                {t.description}
              </p>
            </button>
          )
        })}
      </div>
    </div>
  )
}
