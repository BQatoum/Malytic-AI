import { NavLink, Outlet } from 'react-router-dom';
import { ParticleCanvas } from '../background/ParticleCanvas';
import './Shell.css';

/* Hex-grid SVG — exact tile from reference HTML */
const HEX_SVG = `<svg xmlns='http://www.w3.org/2000/svg' width='56' height='100' viewBox='0 0 56 100'><g fill='none' stroke='%23ffffff' stroke-opacity='0.55' stroke-width='1'><path d='M28 66L0 50L0 16L28 0L56 16L56 50L28 66L28 100'/><path d='M28 0L28 34L0 50L0 84L28 100L56 84L56 50L28 34'/></g></svg>`;
const HEX_URL = `url("data:image/svg+xml,${HEX_SVG}")`;

/* Shield / logo icon */
function ShieldIcon() {
  return (
    <svg width="22" height="22" viewBox="0 0 24 24" fill="none" aria-hidden="true"
      style={{ filter: 'drop-shadow(0 0 9px rgba(225,29,42,0.55))' }}>
      <path d="M12 2L4 6v6c0 5.25 3.5 10.15 8 11 4.5-.85 8-5.75 8-11V6L12 2z"
        stroke="#E11D2A" strokeWidth="1.5" strokeLinejoin="round" fill="rgba(225,29,42,0.08)" />
      <path d="M9 12l2 2 4-4" stroke="#E11D2A" strokeWidth="1.5"
        strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

export function Shell() {
  return (
    <>
      <ParticleCanvas />

      {/* Corner hex-grid motifs — exact from reference */}
      <div className="hex-corner hex-corner--tl" aria-hidden="true"
        style={{ backgroundImage: HEX_URL }} />
      <div className="hex-corner hex-corner--br" aria-hidden="true"
        style={{ backgroundImage: HEX_URL }} />

      <div className="shell">
        {/* ── Nav bar ─────────────────────────────────────────────────── */}
        <nav className="shell-nav" role="navigation" aria-label="Main navigation">
          <div className="shell-nav__inner">
            {/* Logo */}
            <NavLink to="/" className="shell-logo" aria-label="Malytic.AI home">
              <ShieldIcon />
              <span className="shell-logo__text">
                Malytic<span className="shell-logo__dot">.AI</span>
              </span>
            </NavLink>

            {/* Right side: live indicator + Analyze nav item */}
            <div className="shell-nav__right">
              {/* SOC status badge */}
              <div className="shell-api-badge" aria-label="SOC status: online">
                <span className="shell-api-badge__dot" aria-hidden="true" />
                <span className="shell-api-badge__label">SOC-04</span>
              </div>

              {/* Single nav item — Analyze */}
              <NavLink
                to="/"
                end
                className={({ isActive }) =>
                  `shell-nav__link${isActive ? ' is-active' : ''}`
                }
              >
                <span className="shell-nav__link-text">Analyze</span>
                <span className="shell-nav__link-bar" aria-hidden="true" />
              </NavLink>
            </div>
          </div>
        </nav>

        {/* ── Page content ────────────────────────────────────────────── */}
        <main className="shell-content" id="main-content">
          <Outlet />
        </main>
      </div>
    </>
  );
}
