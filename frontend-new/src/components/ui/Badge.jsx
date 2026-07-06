import './Badge.css';

const VARIANTS = {
  default:      'badge--default',
  accent:       'badge--accent',
  running:      'badge--running',
  done:         'badge--done',
  failed:       'badge--failed',
  pending:      'badge--pending',
  score:        'badge--score',
  paused_osint: 'badge--paused',
};

export function Badge({ children, variant = 'default', className = '' }) {
  return (
    <span className={`badge ${VARIANTS[variant] ?? VARIANTS.default} ${className}`}>
      {/* Static X icon distinguishes failed from running (which uses a CSS pulse dot) */}
      {variant === 'failed' && (
        <svg width="8" height="8" viewBox="0 0 8 8" fill="none" aria-hidden="true">
          <path d="M1 1l6 6M7 1L1 7" stroke="currentColor" strokeWidth="1.5"
            strokeLinecap="round" />
        </svg>
      )}
      {children}
    </span>
  );
}

/** Score 0–10 → colour variant */
export function ScoreBadge({ score }) {
  const n = Number(score);
  const variant = n >= 7 ? 'failed' : n >= 4 ? 'running' : 'done';
  return <Badge variant={variant}>{isNaN(n) ? '—' : n.toFixed(1)}</Badge>;
}
