import './Spinner.css';

export function Spinner({ size = 20, color = 'var(--accent)' }) {
  return (
    <span
      className="spinner"
      style={{ '--sz': `${size}px`, '--clr': color }}
      role="status"
      aria-label="Loading"
    />
  );
}
