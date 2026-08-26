/**
 * Skeleton placeholders.
 *
 * A spinner says "something is happening" and nothing else: it is the same
 * shape on every screen, so the layout still jumps when the data lands and the
 * wait feels longer than it is. A skeleton says "content of *this* shape is
 * coming", holds the space the real content will occupy, and lets the eye
 * settle before the data arrives.
 *
 * These deliberately keep the app's neo-brutalist language -- 3px black
 * borders, square corners, hard offset shadows -- so a loading dashboard reads
 * as the same product as a loaded one, not as a generic grey placeholder.
 *
 * Spinners are NOT removed everywhere. The rule applied across this codebase:
 *
 *   skeleton  content is being fetched and its shape is known in advance
 *   spinner   an action the user just triggered is in flight (submit, refresh)
 *   progress  determinate work with a real percentage (a running scan)
 *
 * A skeleton in a submit button would be nonsense -- there is no incoming
 * content to outline -- so those stay as spinners.
 */

/**
 * One shimmering block. Everything else here composes this.
 *
 * `className` carries the size, so callers shape the block to whatever they
 * are standing in for.
 */
export function Skeleton({ className = '', bordered = false }) {
  return (
    <div
      className={`skeleton-shimmer ${bordered ? 'border-3 border-black' : ''} ${className}`}
      aria-hidden="true"
    />
  )
}

/**
 * Wrapper that announces loading state to assistive technology.
 *
 * The blocks themselves are aria-hidden: a screen reader gains nothing from
 * being told about twelve grey rectangles. One live region saying what is
 * loading is the useful signal, so every skeleton view is wrapped in this.
 */
export function SkeletonRegion({ label = 'Loading', children, className = '' }) {
  return (
    <div role="status" aria-live="polite" aria-busy="true" className={className}>
      <span className="sr-only">{label}</span>
      {children}
    </div>
  )
}

/** A run of text lines, last one short so it reads as a paragraph. */
export function SkeletonText({ lines = 3, className = '' }) {
  return (
    <div className={`space-y-2 ${className}`}>
      {Array.from({ length: lines }).map((_, i) => (
        <Skeleton
          key={i}
          className={`h-3 ${i === lines - 1 ? 'w-2/3' : 'w-full'}`}
        />
      ))}
    </div>
  )
}

/** The dashboard's four coloured stat tiles. */
export function SkeletonStatCards({ count = 4 }) {
  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
      {Array.from({ length: count }).map((_, i) => (
        <div
          key={i}
          className="bg-white border-3 border-black p-5 shadow-neb-sm"
        >
          <div className="flex items-center gap-3">
            <Skeleton className="w-6 h-6 flex-shrink-0" />
            <div className="flex-1 min-w-0 space-y-2">
              <Skeleton className="h-6 w-16" />
              <Skeleton className="h-2 w-24" />
            </div>
          </div>
        </div>
      ))}
    </div>
  )
}

/** A bordered panel with a heading and a body area of a given height. */
export function SkeletonPanel({ bodyHeight = 'h-[200px]', className = '' }) {
  return (
    <div className={`bg-white border-3 border-black p-5 shadow-neb ${className}`}>
      <Skeleton className="h-3 w-40 mb-4" />
      <Skeleton className={`w-full ${bodyHeight}`} />
    </div>
  )
}

/** Rows inside an already-bordered list container. */
export function SkeletonRows({ rows = 6 }) {
  return (
    <>
      {Array.from({ length: rows }).map((_, i) => (
        <div
          key={i}
          className="px-5 py-4 flex items-center justify-between gap-4"
        >
          <div className="flex items-center gap-4 flex-1 min-w-0">
            <Skeleton className="h-3 w-32 flex-shrink-0" />
            <Skeleton className="h-3 flex-1 min-w-0" />
          </div>
          <Skeleton className="h-3 w-12 flex-shrink-0" />
        </div>
      ))}
    </>
  )
}

/** Stand-in for a self-contained bordered card, e.g. a settings panel. */
export function SkeletonCard({ lines = 3, className = '' }) {
  return (
    <div className={`bg-white border-3 border-black p-6 shadow-neb ${className}`}>
      <Skeleton className="h-4 w-48 mb-4" />
      <SkeletonText lines={lines} />
    </div>
  )
}

export default Skeleton
