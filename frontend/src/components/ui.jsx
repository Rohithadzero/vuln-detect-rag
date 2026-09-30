import { forwardRef } from 'react'
import { Loader2, ChevronDown } from 'lucide-react'

// Shared primitives. Pages compose these instead of styling their own
// buttons and panels, so one change here restyles the whole app.

export const cx = (...parts) => parts.filter(Boolean).join(' ')

const BUTTON_VARIANTS = {
  primary: 'bg-accent text-accent-fg hover:bg-accent-hover border border-transparent',
  secondary: 'bg-surface text-ink border border-line hover:bg-hover hover:border-line-strong',
  ghost: 'text-ink-muted hover:text-ink hover:bg-hover border border-transparent',
  danger: 'bg-crit-solid text-white hover:opacity-90 border border-transparent',
}

const BUTTON_SIZES = {
  sm: 'h-8 px-3 text-[13px] gap-1.5',
  md: 'h-9 px-3.5 text-sm gap-2',
  lg: 'h-10 px-4 text-sm gap-2',
}

export const Button = forwardRef(function Button(
  { variant = 'secondary', size = 'md', icon: Icon, loading = false, className, children, disabled, type = 'button', ...props },
  ref
) {
  return (
    <button
      ref={ref}
      type={type}
      disabled={disabled || loading}
      className={cx(
        'inline-flex items-center justify-center rounded-ctl font-medium whitespace-nowrap',
        'transition-colors duration-150 disabled:opacity-50 disabled:cursor-not-allowed',
        BUTTON_VARIANTS[variant],
        BUTTON_SIZES[size],
        className
      )}
      {...props}
    >
      {loading ? (
        <Loader2 className="w-4 h-4 animate-spin" aria-hidden="true" />
      ) : (
        Icon && <Icon className="w-4 h-4 flex-shrink-0" aria-hidden="true" />
      )}
      {children}
    </button>
  )
})

export function IconButton({ label, icon: Icon, className, size = 'md', ...props }) {
  return (
    <button
      type="button"
      aria-label={label}
      title={label}
      className={cx(
        'inline-flex items-center justify-center rounded-ctl text-ink-muted hover:text-ink hover:bg-hover',
        'transition-colors duration-150 disabled:opacity-50',
        size === 'sm' ? 'w-8 h-8' : 'w-9 h-9',
        className
      )}
      {...props}
    >
      <Icon className="w-4 h-4" aria-hidden="true" />
    </button>
  )
}

export function Card({ as: Tag = 'section', className, children, ...props }) {
  return (
    <Tag className={cx('bg-surface border border-line rounded-card shadow-card', className)} {...props}>
      {children}
    </Tag>
  )
}

export function CardHeader({ title, description, icon: Icon, actions, className }) {
  return (
    <div className={cx('flex items-start justify-between gap-3 px-5 pt-4 pb-3', className)}>
      <div className="min-w-0">
        <h2 className="text-sm font-semibold text-ink flex items-center gap-2">
          {Icon && <Icon className="w-4 h-4 text-ink-subtle flex-shrink-0" aria-hidden="true" />}
          {title}
        </h2>
        {description && <p className="text-[13px] text-ink-muted mt-0.5">{description}</p>}
      </div>
      {actions && <div className="flex items-center gap-2 flex-shrink-0">{actions}</div>}
    </div>
  )
}

const BADGE_TONES = {
  neutral: 'bg-hover text-ink-muted',
  accent: 'bg-accent-soft text-accent-text',
  crit: 'bg-crit-soft text-crit',
  high: 'bg-high-soft text-high',
  med: 'bg-med-soft text-med',
  low: 'bg-low-soft text-low',
  ok: 'bg-ok-soft text-ok',
}

export function Badge({ tone = 'neutral', icon: Icon, className, children, ...props }) {
  return (
    <span
      className={cx(
        'inline-flex items-center gap-1 h-5 px-2 rounded-full text-2xs font-medium whitespace-nowrap',
        BADGE_TONES[tone],
        className
      )}
      {...props}
    >
      {Icon && <Icon className="w-3 h-3" aria-hidden="true" />}
      {children}
    </span>
  )
}

export const SEVERITY_TONE = { CRITICAL: 'crit', HIGH: 'high', MEDIUM: 'med', LOW: 'low', INFO: 'neutral' }
const SEVERITY_LABEL = { CRITICAL: 'Critical', HIGH: 'High', MEDIUM: 'Medium', LOW: 'Low', INFO: 'Info' }

export function SeverityBadge({ severity, className }) {
  const key = (severity || 'INFO').toUpperCase()
  return (
    <Badge tone={SEVERITY_TONE[key] || 'neutral'} className={className}>
      {SEVERITY_LABEL[key] || severity}
    </Badge>
  )
}

const STATUS = {
  completed: { tone: 'ok', label: 'Completed' },
  running: { tone: 'accent', label: 'Running' },
  pending: { tone: 'neutral', label: 'Queued' },
  failed: { tone: 'crit', label: 'Failed' },
  cancelled: { tone: 'neutral', label: 'Stopped' },
}

export function StatusBadge({ status }) {
  const s = STATUS[status] || { tone: 'neutral', label: status }
  return <Badge tone={s.tone}>{s.label}</Badge>
}

const FIELD = cx(
  'w-full h-9 rounded-ctl border border-line bg-surface text-ink text-sm',
  'placeholder:text-ink-subtle transition-colors duration-150',
  'hover:border-line-strong focus:border-accent focus:outline-none focus-visible:outline-2',
  'disabled:opacity-60 disabled:cursor-not-allowed'
)

export const Input = forwardRef(function Input({ icon: Icon, className, inputClassName, ...props }, ref) {
  if (!Icon) return <input ref={ref} className={cx(FIELD, 'px-3', className)} {...props} />
  return (
    <div className={cx('relative', className)}>
      <Icon className="w-4 h-4 text-ink-subtle absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" aria-hidden="true" />
      <input ref={ref} className={cx(FIELD, 'pl-9 pr-3', inputClassName)} {...props} />
    </div>
  )
})

export function Select({ className, children, ...props }) {
  return (
    <div className={cx('relative', className)}>
      <select className={cx(FIELD, 'appearance-none pl-3 pr-8 cursor-pointer')} {...props}>
        {children}
      </select>
      <ChevronDown className="w-4 h-4 text-ink-subtle absolute right-2.5 top-1/2 -translate-y-1/2 pointer-events-none" aria-hidden="true" />
    </div>
  )
}

export function Label({ htmlFor, children, hint }) {
  return (
    <label htmlFor={htmlFor} className="block text-[13px] font-medium text-ink mb-1.5">
      {children}
      {hint && <span className="font-normal text-ink-subtle ml-1.5">{hint}</span>}
    </label>
  )
}

export function Toggle({ on, onChange, busy, disabled, label }) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={on}
      aria-label={label}
      disabled={busy || disabled}
      onClick={() => onChange(!on)}
      className={cx(
        'relative inline-flex w-10 h-6 rounded-full flex-shrink-0 transition-colors duration-150',
        'disabled:opacity-40 disabled:cursor-not-allowed',
        on ? 'bg-accent' : 'bg-line-strong'
      )}
    >
      <span
        className={cx(
          'absolute top-0.5 left-0.5 w-5 h-5 rounded-full bg-[oklch(0.985_0.003_265)] shadow-card flex items-center justify-center',
          'transition-transform duration-200 ease-out',
          on && 'translate-x-4'
        )}
      >
        {busy && <Loader2 className="w-3 h-3 animate-spin text-ink-muted" aria-hidden="true" />}
      </span>
    </button>
  )
}

// A row of mutually exclusive options: tabs, filters, theme choice.
export function Segmented({ options, value, onChange, label, size = 'md', className, role = 'tablist' }) {
  const itemRole = role === 'tablist' ? 'tab' : 'radio'
  return (
    <div
      role={role}
      aria-label={label}
      className={cx('inline-flex items-center gap-0.5 p-0.5 rounded-ctl bg-sunken border border-line max-w-full overflow-x-auto', className)}
    >
      {options.map((opt) => {
        const active = opt.value === value
        return (
          <button
            key={opt.value}
            type="button"
            role={itemRole}
            aria-selected={itemRole === 'tab' ? active : undefined}
            aria-checked={itemRole === 'radio' ? active : undefined}
            onClick={() => onChange(opt.value)}
            className={cx(
              'inline-flex items-center gap-1.5 rounded-[8px] font-medium whitespace-nowrap transition-colors duration-150',
              size === 'sm' ? 'h-7 px-2.5 text-xs' : 'h-8 px-3 text-[13px]',
              active ? 'bg-surface text-ink shadow-card' : 'text-ink-muted hover:text-ink'
            )}
          >
            {opt.icon && <opt.icon className="w-3.5 h-3.5" aria-hidden="true" />}
            {opt.label}
            {opt.count !== undefined && (
              <span className={cx('tabular text-2xs', active ? 'text-ink-muted' : 'text-ink-subtle')}>{opt.count}</span>
            )}
          </button>
        )
      })}
    </div>
  )
}

export function PageHeader({ title, description, actions }) {
  return (
    <header className="flex flex-col sm:flex-row sm:items-end justify-between gap-3 mb-6">
      <div className="min-w-0">
        <h1 className="text-2xl font-semibold tracking-tight text-ink">{title}</h1>
        {description && <p className="text-sm text-ink-muted mt-1">{description}</p>}
      </div>
      {actions && <div className="flex items-center gap-2 flex-shrink-0">{actions}</div>}
    </header>
  )
}

export function EmptyState({ icon: Icon, title, children, action, className }) {
  return (
    <div className={cx('flex flex-col items-center justify-center text-center px-6 py-12', className)}>
      {Icon && (
        <div className="w-10 h-10 rounded-ctl bg-sunken border border-line flex items-center justify-center mb-3">
          <Icon className="w-5 h-5 text-ink-subtle" aria-hidden="true" />
        </div>
      )}
      <p className="text-sm font-medium text-ink">{title}</p>
      {children && <p className="text-[13px] text-ink-muted mt-1 max-w-sm">{children}</p>}
      {action && <div className="mt-4">{action}</div>}
    </div>
  )
}

const CALLOUT_TONES = {
  info: 'bg-sunken border-line text-ink',
  warn: 'bg-med-soft border-med/25 text-ink',
  crit: 'bg-crit-soft border-crit/25 text-ink',
  ok: 'bg-ok-soft border-ok/25 text-ink',
}
const CALLOUT_ICON = { info: 'text-ink-subtle', warn: 'text-med', crit: 'text-crit', ok: 'text-ok' }

export function Callout({ tone = 'info', icon: Icon, title, children, className, ...props }) {
  return (
    <div className={cx('flex items-start gap-3 rounded-card border px-4 py-3', CALLOUT_TONES[tone], className)} {...props}>
      {Icon && <Icon className={cx('w-4 h-4 mt-0.5 flex-shrink-0', CALLOUT_ICON[tone])} aria-hidden="true" />}
      <div className="min-w-0 text-[13px]">
        {title && <p className="font-medium">{title}</p>}
        {children && <div className={cx('text-ink-muted break-words', title && 'mt-0.5')}>{children}</div>}
      </div>
    </div>
  )
}

// Several numbers in one bordered strip. Deliberately not a row of coloured
// tiles: the numbers are the point, and tone is reserved for severity.
export function StatStrip({ items, className }) {
  return (
    <Card className={cx('overflow-hidden', className)} as="div">
      <dl className="grid grid-cols-2 sm:flex">
        {items.map((it) => (
          <div key={it.label} className="px-5 py-4 min-w-0 sm:flex-1 border-line sm:[&:not(:first-child)]:border-l">
            <dt className="text-xs text-ink-muted">{it.label}</dt>
            <dd className={cx('text-xl font-semibold tabular mt-1', it.tone ? `text-${it.tone}` : 'text-ink')}>{it.value}</dd>
          </div>
        ))}
      </dl>
    </Card>
  )
}

export function ProgressBar({ value = 0, label }) {
  const v = Math.max(0, Math.min(100, value))
  return (
    <div
      role="progressbar"
      aria-label={label}
      aria-valuenow={v}
      aria-valuemin={0}
      aria-valuemax={100}
      className="h-1.5 w-full rounded-full bg-hover overflow-hidden"
    >
      <div className="h-full rounded-full bg-accent transition-[width] duration-500 ease-out" style={{ width: `${v}%` }} />
    </div>
  )
}
