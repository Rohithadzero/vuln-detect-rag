/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        dark: {
          50: '#f8fafc',
          100: '#f1f5f9',
          200: '#e2e8f0',
          300: '#cbd5e1',
          400: '#94a3b8',
          500: '#64748b',
          600: '#475569',
          700: '#334155',
          800: '#1e293b',
          900: '#0f172a',
          950: '#020617',
        },
        neo: {
          yellow: '#fde047',
          pink: '#f472b6',
          cyan: '#22d3ee',
          green: '#4ade80',
          purple: '#a78bfa',
          orange: '#fb923c',
          red: '#ef4444',
          blue: '#60a5fa',
        }
      },
      fontFamily: {
        display: ['Manrope', 'Inter', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
      },
      borderWidth: {
        '3': '3px',
      },
      boxShadow: {
        'neb': '6px 6px 0px 0px var(--color-border)',
        'neb-sm': '4px 4px 0px 0px var(--color-border)',
        'neb-xs': '3px 3px 0px 0px var(--color-border)',
        'neb-hover': '2px 2px 0px 0px var(--color-border)',
      }
    },
  },
  plugins: [],
}
