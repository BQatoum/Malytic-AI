import { useState, useCallback, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { X } from 'lucide-react';
import { submitSample } from '../api/client';
import { AdvancedModal } from '../components/advanced/AdvancedModal';
import './Upload.css';

/* ── Bug / malware SVG — floating inside scan ring ────────────────────────── */
function BugSVG() {
  return (
    <svg viewBox="0 0 64 64" fill="none" xmlns="http://www.w3.org/2000/svg"
      width="86" height="86" aria-hidden="true" className="bug-svg">
      <path d="M28 12C23 6 19 7 16 4" stroke="#E11D2A" strokeWidth="2.2" strokeLinecap="round"/>
      <path d="M36 12C41 6 45 7 48 4" stroke="#E11D2A" strokeWidth="2.2" strokeLinecap="round"/>
      <circle cx="32" cy="15" r="4.5" stroke="#E11D2A" strokeWidth="2"
        fill="rgba(225,29,42,0.18)" />
      <ellipse cx="32" cy="38" rx="12" ry="18" stroke="#E11D2A" strokeWidth="2"
        fill="rgba(225,29,42,0.10)" />
      <path d="M32 23V53" stroke="#E11D2A" strokeWidth="1.4" strokeLinecap="round"/>
      <path d="M22 29C27 33 37 33 42 29" stroke="#E11D2A" strokeWidth="1.4" strokeLinecap="round"/>
      <path d="M20 38C27 40 37 40 44 38" stroke="#E11D2A" strokeWidth="1.2" strokeLinecap="round" opacity="0.6"/>
      <path d="M20 31L7 24"  stroke="#E11D2A" strokeWidth="1.4" strokeLinecap="round"/>
      <path d="M19 39L6 41"  stroke="#E11D2A" strokeWidth="1.4" strokeLinecap="round"/>
      <path d="M21 48L9 56"  stroke="#E11D2A" strokeWidth="1.4" strokeLinecap="round"/>
      <path d="M44 31L57 24" stroke="#E11D2A" strokeWidth="1.4" strokeLinecap="round"/>
      <path d="M45 39L58 41" stroke="#E11D2A" strokeWidth="1.4" strokeLinecap="round"/>
      <path d="M43 48L55 56" stroke="#E11D2A" strokeWidth="1.4" strokeLinecap="round"/>
    </svg>
  );
}

function CheckSVG() {
  return (
    <svg viewBox="0 0 48 48" fill="none" width="64" height="64" aria-hidden="true">
      <circle cx="24" cy="24" r="22" stroke="#2FBF71" strokeWidth="1.5"
        fill="rgba(47,191,113,0.06)" />
      <path d="M14 24l7 7 13-14" stroke="#2FBF71" strokeWidth="2.2"
        strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

/* Lock icon for password field */
function LockIcon() {
  return (
    <svg width="16" height="16" viewBox="0 0 16 16" fill="none" aria-hidden="true"
      style={{ flexShrink: 0, color: 'rgba(255,255,255,0.32)' }}>
      <rect x="3" y="7" width="10" height="8" rx="1.5" stroke="currentColor" strokeWidth="1.3"/>
      <path d="M5.5 7V5a2.5 2.5 0 015 0v2" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round"/>
    </svg>
  );
}

/* ── Phase data ────────────────────────────────────────────────────────────── */
const PHASES = [
  { n:'01', name:'Static',      desc:'PE / strings / packing analysis' },
  { n:'02', name:'Dynamic',     desc:'Live sandbox detonation + screenshots' },
  { n:'03', name:'OSINT',       desc:'Threat-intel enrichment' },
  { n:'04', name:'Correlation', desc:'Cross-sample IOC linking' },
  { n:'05', name:'Detection',   desc:'Auto-generated YARA / Sigma rules' },
  { n:'06', name:'Report',      desc:'Analyst-ready threat summary' },
  { n:'07', name:'Elastic',     desc:'Indexed straight to your SIEM' },
];

const PHASE_ICONS = [
  /* Static */
  <svg viewBox="0 0 20 20" fill="none" width="20" height="20">
    <circle cx="8.5" cy="8.5" r="5" stroke="currentColor" strokeWidth="1.5"/>
    <path d="M12.5 12.5L17 17" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"/>
  </svg>,
  /* Dynamic */
  <svg viewBox="0 0 20 20" fill="none" width="20" height="20">
    <path d="M7 4l9 6-9 6V4z" stroke="currentColor" strokeWidth="1.5" strokeLinejoin="round"/>
  </svg>,
  /* OSINT */
  <svg viewBox="0 0 20 20" fill="none" width="20" height="20">
    <circle cx="10" cy="10" r="7" stroke="currentColor" strokeWidth="1.5"/>
    <path d="M10 3c-2 2-3 5-3 7s1 5 3 7M10 3c2 2 3 5 3 7s-1 5-3 7M3 10h14"
      stroke="currentColor" strokeWidth="1.2" strokeLinecap="round"/>
  </svg>,
  /* Correlation */
  <svg viewBox="0 0 20 20" fill="none" width="20" height="20">
    <circle cx="4" cy="10" r="2" stroke="currentColor" strokeWidth="1.5"/>
    <circle cx="16" cy="5" r="2" stroke="currentColor" strokeWidth="1.5"/>
    <circle cx="16" cy="15" r="2" stroke="currentColor" strokeWidth="1.5"/>
    <path d="M6 10h3m1-3.5l4-1.5M10 10.5l4 3" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round"/>
  </svg>,
  /* Detection */
  <svg viewBox="0 0 20 20" fill="none" width="20" height="20">
    <path d="M10 2L4 5v5c0 4.2 2.8 8.1 6 8.8 3.2-.7 6-4.6 6-8.8V5L10 2z"
      stroke="currentColor" strokeWidth="1.5" strokeLinejoin="round"/>
    <path d="M7.5 10l2 2 3-3" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"/>
  </svg>,
  /* Report */
  <svg viewBox="0 0 20 20" fill="none" width="20" height="20">
    <rect x="4" y="2" width="12" height="16" rx="2" stroke="currentColor" strokeWidth="1.5"/>
    <path d="M7 7h6M7 10h6M7 13h4" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round"/>
  </svg>,
  /* Elastic */
  <svg viewBox="0 0 20 20" fill="none" width="20" height="20">
    <ellipse cx="10" cy="5.5" rx="6" ry="2.5" stroke="currentColor" strokeWidth="1.5"/>
    <path d="M4 5.5v4c0 1.38 2.69 2.5 6 2.5s6-1.12 6-2.5v-4" stroke="currentColor" strokeWidth="1.5"/>
    <path d="M4 9.5v4c0 1.38 2.69 2.5 6 2.5s6-1.12 6-2.5v-4" stroke="currentColor" strokeWidth="1.5"/>
  </svg>,
];

/* ── Capabilities ──────────────────────────────────────────────────────────── */
const CAPS = [
  {
    title: 'Live sandbox detonation',
    body:  'Files are detonated in an isolated VM with full behavioral capture, network traces and runtime screenshots.',
    icon: (
      <svg viewBox="0 0 22 22" fill="none" width="22" height="22">
        <rect x="3" y="7" width="16" height="11" rx="2" stroke="#E11D2A" strokeWidth="1.5"/>
        <path d="M7 7V5a4 4 0 018 0v2" stroke="#E11D2A" strokeWidth="1.5" strokeLinecap="round"/>
        <path d="M11 12v2" stroke="#E11D2A" strokeWidth="1.8" strokeLinecap="round"/>
        <circle cx="11" cy="11.5" r="1" fill="#E11D2A"/>
      </svg>
    ),
  },
  {
    title: 'AI threat interpretation',
    body:  'A model reasons over every signal to explain intent, malware family and severity in plain English.',
    icon: (
      <svg viewBox="0 0 22 22" fill="none" width="22" height="22">
        <circle cx="11" cy="11" r="8" stroke="#E11D2A" strokeWidth="1.5"/>
        <path d="M8 9.5c0-1.66 1.34-3 3-3s3 1.34 3 3c0 1.5-1.2 2.5-3 3v1.5"
          stroke="#E11D2A" strokeWidth="1.5" strokeLinecap="round"/>
        <circle cx="11" cy="16" r="0.8" fill="#E11D2A"/>
      </svg>
    ),
  },
  {
    title: 'Auto-generated detection rules',
    body:  'Ships ready-to-deploy YARA and Sigma rules, each mapped to the relevant MITRE ATT&CK techniques.',
    icon: (
      <svg viewBox="0 0 22 22" fill="none" width="22" height="22">
        <path d="M11 2L4 5.5v5.5c0 4.4 3 8.5 7 9.5 4-1 7-5.1 7-9.5V5.5L11 2z"
          stroke="#E11D2A" strokeWidth="1.5" strokeLinejoin="round"/>
        <path d="M8 11l2 2 4-4" stroke="#E11D2A" strokeWidth="1.6" strokeLinecap="round"/>
      </svg>
    ),
  },
  {
    title: 'Analyst-augmented analysis',
    body:  'Bring your own static findings or internal IOC database — the platform adapts the pipeline to your tradecraft and completes the rest.',
    icon: (
      <svg viewBox="0 0 22 22" fill="none" width="22" height="22">
        <circle cx="9" cy="8" r="3.5" stroke="#E11D2A" strokeWidth="1.5"/>
        <path d="M3 19c0-3.31 2.69-6 6-6" stroke="#E11D2A" strokeWidth="1.5" strokeLinecap="round"/>
        <path d="M16 13v6M13 16h6" stroke="#E11D2A" strokeWidth="1.8" strokeLinecap="round"/>
      </svg>
    ),
  },
];

/* ── Main page ───────────────────────────────────────────────────────────────── */
export function Upload() {
  const [file, setFile]           = useState(null);
  const [password, setPassword]   = useState('infected');
  const [dragging, setDragging]   = useState(false);
  const [submitting, setSubmit]   = useState(false);
  const [error, setError]         = useState(null);
  const [showModal, setShowModal] = useState(false);
  const inputRef = useRef(null);
  const navigate = useNavigate();

  // Accept a file and immediately surface the analysis-mode modal.
  const accept = useCallback(f => {
    if (!f) return;
    setFile(f);
    setError(null);
    setShowModal(true);
  }, []);

  const onDrop = useCallback(e => {
    e.preventDefault(); setDragging(false);
    const f = e.dataTransfer.files?.[0]; if (f) accept(f);
  }, [accept]);
  const onDragOver    = e => { e.preventDefault(); setDragging(true); };
  const onDragLeave   = () => setDragging(false);
  const onInputChange = e => { const f = e.target.files?.[0]; if (f) accept(f); };

  // Form submit re-opens the modal when a file is already selected.
  const onSubmit = e => {
    e.preventDefault();
    if (!file) return;
    setShowModal(true);
  };

  // Called by the modal with the chosen options (may include iocFile).
  const handleModalSubmit = async (options = {}) => {
    setShowModal(false);
    setSubmit(true);
    setError(null);
    try {
      const { case_id } = await submitSample(file, password, options);
      navigate(`/live/${case_id}`);
    } catch (err) {
      setError(err.message ?? 'Upload failed');
      setSubmit(false);
    }
  };

  // Cancel clears all file state so the page is fully reset — including the
  // hidden input's .value, otherwise re-selecting the same file fires no onChange.
  const handleModalCancel = () => {
    setShowModal(false);
    setFile(null);
    setError(null);
    if (inputRef.current) inputRef.current.value = '';
  };

  return (
    <div className="upload-page">

      {showModal && file && (
        <AdvancedModal
          file={file}
          onCancel={handleModalCancel}
          onSubmit={handleModalSubmit}
        />
      )}

      {/* ── Hero ─────────────────────────────────────────────────────────── */}
      <div className="upload-hero">

        {/* Left — text + form */}
        <div className="upload-hero__left">
          <p className="eyebrow">// THREAT ANALYSIS CONSOLE</p>
          <h1 className="upload-title">
            AI Malware<br />Analyzer
          </h1>
          <p className="upload-subtitle">
            Submit a file for AI-powered threat analysis across a 7-phase pipeline —
            from static inspection to live detonation and indexed intelligence.
            Analysts can bring their own static findings and internal IOC database
            to tailor the pipeline to their tradecraft.
          </p>

          <form className="upload-form" onSubmit={onSubmit} noValidate>
            <div className="upload-field-group">
              <p className="upload-field-label">ARCHIVE PASSWORD</p>
              <div className="upload-input-wrap">
                <LockIcon />
                <input
                  type="text"
                  className="upload-input"
                  value={password}
                  onChange={e => setPassword(e.target.value)}
                  placeholder="infected"
                  autoComplete="off"
                  spellCheck={false}
                  aria-label="Archive password"
                />
              </div>
              <p className="upload-hint">
                Password-protected archives are extracted before scanning — malware is often shipped zipped.
              </p>
            </div>

            {error && <p className="upload-error" role="alert">{error}</p>}

            <button
              type="submit"
              className={`upload-btn${submitting ? ' upload-btn--loading' : ''}`}
              disabled={!file || submitting}
              aria-busy={submitting}
            >
              {submitting ? (
                <>
                  <span className="upload-btn__spinner" aria-hidden="true" />
                  Submitting…
                </>
              ) : file ? (
                'CONFIGURE & RUN →'
              ) : (
                'DROP A FILE TO BEGIN'
              )}
            </button>
          </form>
        </div>

        {/* Right — scan ring */}
        <div className="scan-wrapper">
          {/* Pulse rings stay outside so they can expand beyond the circle */}
          <div className="scan-pulse scan-pulse--1" aria-hidden="true" />
          <div className="scan-pulse scan-pulse--2" aria-hidden="true" />
          <div className="scan-deco-ring" aria-hidden="true" />

          <div
            className={`scan-circle${dragging ? ' scan-circle--drag' : ''}${file ? ' scan-circle--filled' : ''}`}
            onClick={() => !file && inputRef.current?.click()}
            onDrop={onDrop}
            onDragOver={onDragOver}
            onDragLeave={onDragLeave}
            role="button"
            tabIndex={0}
            aria-label={file ? `Selected: ${file.name}` : 'Click or drag to upload a file'}
            onKeyDown={e => e.key === 'Enter' && !file && inputRef.current?.click()}
          >
            <input ref={inputRef} type="file" className="scan-input"
              onChange={onInputChange} aria-hidden="true" tabIndex={-1} />

            {/* Glow blob inside circle — clipped by overflow:hidden, no bleed */}
            <div className="scan-glow-blob" aria-hidden="true" />
            <div className="scan-radar" aria-hidden="true" />

            <div className="scan-content">
              {!file ? (
                <>
                  <div className="scan-bug-wrap" aria-hidden="true">
                    <div className="scan-line" aria-hidden="true" />
                    <BugSVG />
                  </div>
                  <p className="scan-label">
                    {dragging ? 'RELEASE TO SCAN' : 'DROP FILE TO SCAN'}
                  </p>
                  <p className="scan-sublabel">
                    or browse — PE, ZIP, DOCX, DOCM, DOC, PDF
                  </p>
                </>
              ) : (
                <>
                  <div style={{ filter: 'drop-shadow(0 0 11px rgba(47,191,113,0.6))' }}>
                    <CheckSVG />
                  </div>
                  <p className="scan-filename">{file.name}</p>
                  <p className="scan-filesize" style={{ color: '#2FBF71' }}>
                    SAMPLE READY
                  </p>
                  <button
                    type="button"
                    className="scan-remove"
                    onClick={e => { e.stopPropagation(); setFile(null); }}
                    aria-label="Remove selected file"
                  >
                    <X size={13} aria-hidden="true" /> Clear
                  </button>
                </>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* ── Pipeline section ─────────────────────────────────────────────── */}
      <section className="pipeline-section">
        <div className="section-header">
          <p className="eyebrow">// ANALYSIS ROADMAP</p>
          <h2 className="section-title">Seven phases. Fully automated.</h2>
          <p className="section-sub">
            From raw sample to indexed intelligence — every step runs end to end,
            no analyst babysitting required.
          </p>
        </div>

        <div className="pipeline-nodes" role="list">
          {/* Connector line sits inside this relative container at top:19px */}
          <div className="pipeline-connector" aria-hidden="true">
            <div className="pipeline-connector__flow" />
          </div>

          {PHASES.map((p, i) => (
            <div key={p.n} className="phase-node" role="listitem">
              {/* Numbered circle — sits ON the connector line */}
              <div className="phase-node__num" aria-hidden="true">{p.n}</div>
              {/* Card — icon + name + desc */}
              <div className="phase-node__card">
                <div className="phase-node__icon" aria-hidden="true">
                  {PHASE_ICONS[i]}
                </div>
                <p className="phase-node__name">{p.name}</p>
                <p className="phase-node__desc">{p.desc}</p>
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* ── Capabilities ─────────────────────────────────────────────────── */}
      <section className="caps-section" aria-label="Platform capabilities">
        <p className="eyebrow">// CAPABILITIES</p>
        <div className="caps-grid">
          {CAPS.map(c => (
            <div key={c.title} className="cap-card">
              <div className="cap-card__icon-wrap" aria-hidden="true">
                {c.icon}
              </div>
              <h3 className="cap-card__title">{c.title}</h3>
              <p className="cap-card__body">{c.body}</p>
            </div>
          ))}
        </div>
      </section>

      {/* ── Footer ────────────────────────────────────────────────────────── */}
      <footer className="upload-footer" aria-label="Site footer">
        <p className="upload-footer__copy">© 2026 Malytic.AI — Threat Intelligence Platform</p>
        <div className="upload-footer__status">
          <span className="upload-footer__dot" aria-hidden="true" />
          <span className="upload-footer__status-text">Sandbox cluster online</span>
          <span className="upload-footer__version">v7.2.1</span>
        </div>
      </footer>

    </div>
  );
}
