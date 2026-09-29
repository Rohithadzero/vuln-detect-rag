/** @type {import('tailwindcss').Config} */

// Every color is a CSS variable holding "L C H", so light and dark mode swap
// in index.css without a single `dark:` variant in the components.
const token = (name) => `oklch(var(--${name}) / <alpha-value>)`

const semantic = (name) => ({
  DEFAULT: token(`${name}-text`),
  soft: token(`${name}-soft`),
  solid: token(`${name}-solid`),
})

export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        canvas: token('canvas'),
        surface: token('surface'),
        sunken: token('sunken'),
        hover: token('hover'),
        line: { DEFAULT: token('line'), strong: token('line-strong') },
        ink: {
          DEFAULT: token('ink'),
          muted: token('ink-muted'),
          subtle: token('ink-subtle'),
        },
        accent: {
          DEFAULT: token('accent'),
          hover: token('accent-hover'),
          fg: token('accent-fg'),
          soft: token('accent-soft'),
          text: token('accent-text'),
        },
        crit: semantic('crit'),
        high: semantic('high'),
        med: semantic('med'),
        low: semantic('low'),
        ok: semantic('ok'),
      },
      fontFamily: {
        sans: ['Geist', 'system-ui', '-apple-system', 'Segoe UI', 'sans-serif'],
        mono: ['"Geist Mono"', 'ui-monospace', 'SFMono-Regular', 'Consolas', 'monospace'],
      },
      fontSize: {
        '2xs': ['0.6875rem', { lineHeight: '1rem' }],
      },
      borderRadius: {
        ctl: '10px',
        card: '12px',
      },
      boxShadow: {
        card: 'var(--shadow-card)',
        pop: 'var(--shadow-pop)',
      },
      maxWidth: {
        prose: '70ch',
      },
    },
  },
  plugins: [],
}
