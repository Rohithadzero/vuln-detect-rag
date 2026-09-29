// The backend accepts a bare domain or public IPv4 only (routes_scan.py
// validate_target). People paste URLs, so the scheme, credentials, path and
// port are dropped here rather than bounced back as a 400.
export function normalizeTarget(input) {
  let t = (input || '').trim()
  t = t.replace(/^[a-z][a-z0-9+.-]*:\/\//i, '')
  t = t.replace(/^[^@/]*@/, '')
  t = t.split(/[/?#]/)[0]
  t = t.replace(/:\d+$/, '')
  return t.replace(/\.$/, '').toLowerCase()
}
