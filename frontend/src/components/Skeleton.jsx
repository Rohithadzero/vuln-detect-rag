/**
 * Skeleton placeholders.
 *
 *   skeleton  content is being fetched and its shape is known in advance
 *   spinner   an action the user just triggered is in flight (submit, refresh)
 *   progress  determinate work with a real percentage (a running scan)
 */
import { Card, cx } from './ui'

export function Skeleton({ className = '' }) {
  return <div className={cx('skeleton-shimmer rounded-md', className)} aria-hidden="true" />
}

/** Announces loading once; the blocks themselves are aria-hidden. */
export function SkeletonRegion({ label = 'Loading', children, className = '' }) {
  return (
    <div role="status" aria-live="polite" aria-busy="true" className={className}>
      <span className="sr-only">{label}</span>
      {children}
    </div>
  )
}

export function SkeletonText({ lines = 3, className = '' }) {
  return (
    <div className={cx('space-y-2', className)}>
      {Array.from({ length: lines }).map((_, i) => (
        <Skeleton key={i} className={cx('h-3', i === lines - 1 ? 'w-2/3' : 'w-full')} />
      ))}
    </div>
  )
}

/** Stand-in for a StatStrip. */
export function SkeletonStatCards({ count = 4 }) {
  return (
    <Card as="div" className="grid grid-cols-2 sm:flex overflow-hidden">
      {Array.from({ length: count }).map((_, i) => (
        <div key={i} className="px-5 py-4 sm:flex-1 space-y-2">
          <Skeleton className="h-3 w-20" />
          <Skeleton className="h-5 w-12" />
        </div>
      ))}
    </Card>
  )
}

export function SkeletonPanel({ bodyHeight = 'h-[200px]', className = '' }) {
  return (
    <Card as="div" className={cx('p-5', className)}>
      <Skeleton className="h-3.5 w-40 mb-4" />
      <Skeleton className={cx('w-full', bodyHeight)} />
    </Card>
  )
}

export function SkeletonRows({ rows = 6 }) {
  return (
    <>
      {Array.from({ length: rows }).map((_, i) => (
        <div key={i} className="px-5 py-3.5 flex items-center justify-between gap-4">
          <div className="flex items-center gap-4 flex-1 min-w-0">
            <Skeleton className="h-3 w-32 flex-shrink-0" />
            <Skeleton className="h-3 flex-1 min-w-0" />
          </div>
          <Skeleton className="h-3 w-10 flex-shrink-0" />
        </div>
      ))}
    </>
  )
}

export function SkeletonCard({ lines = 3, className = '' }) {
  return (
    <Card as="div" className={cx('p-5', className)}>
      <Skeleton className="h-3.5 w-48 mb-4" />
      <SkeletonText lines={lines} />
    </Card>
  )
}

export default Skeleton
