import { useCallback, useRef, useState } from 'react';
import { useParams, useNavigate, Link } from 'react-router-dom';
import { AlertTriangle } from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';
import { getCase, intermediateFindingsUrl, iocExportUrl, resumeWithOsint } from '../api/client';
import { usePolling } from '../hooks/usePolling';
import './LiveAnalysis.css';

const TERMINAL = ['complete', 'failed'];

/* ── Phase metadata — keyed by backend short names (phase.name in pipeline.py) */
const PHASE_META = {
  static:      { label: 'Static Analysis',  sub: 'Parsing binary headers, strings, entropy and packing signals' },
  dynamic:     { label: 'Dynamic Analysis', sub: 'Live sandbox detonation — capturing process tree & network traffic' },
  osint:       { label: 'OSINT Research',   sub: 'Querying VirusTotal, MalwareBazaar, MISP, OTX and Abuse.ch' },
  correlation: { label: 'Correlation',      sub: 'Fusing all phases — mapping MITRE ATT&CK TTPs and attributing family' },
  detection:   { label: 'Detection Eng.',   sub: 'Auto-generating YARA, Sigma and Suricata detection rules' },
  report:      { label: 'Report',           sub: 'Rendering dual-audience executive + technical threat report' },
  elastic:     { label: 'Elastic Push',     sub: 'Indexing IOCs and loading detection rules into Kibana SIEM' },
};

/* Backend short phase names from _PHASES registry in pipeline.py */
const PHASE_ORDER = ['static','dynamic','osint','correlation','detection','report','elastic'];

/* Phase names that are valid pipeline phases (not generic status strings) */
const KNOWN_PHASES = new Set(PHASE_ORDER);

/* ── Determine current running phase from status ─────────────────────────── */
// Backend writes active phase short-name to status.phase (e.g. "static", "dynamic").
// Generic strings ("running","done","partial") may also appear — ignore those.
function getCurrentPhase(status, pipelineStatus) {
  if (!status) return 'static';
  if (pipelineStatus === 'complete') return '__done__';
  if (pipelineStatus === 'failed')   return '__failed__';

  const completed = status.completed ?? [];
  const failed    = (status.failed   ?? []).map(f => f.phase);

  // Use status.phase only when it's a real pipeline phase not yet completed
  if (status.phase && KNOWN_PHASES.has(status.phase) && !completed.includes(status.phase)) {
    return status.phase;
  }

  // Between phases or before first phase: find first non-completed, non-failed phase
  for (const p of PHASE_ORDER) {
    if (!completed.includes(p) && !failed.includes(p)) return p;
  }
  return '__done__';
}

/* ── Phase step state ────────────────────────────────────────────────────── */
function phaseState(phaseName, status, pipelineStatus, caseData) {
  if (!status) return 'pending';
  const completed = status.completed ?? [];
  const failed    = (status.failed ?? []).map(f => f.phase);
  if (completed.includes(phaseName)) return 'done';
  if (failed.includes(phaseName))    return 'failed';
  // Analyst-provided OSINT: resume_pipeline skips _run_osint entirely so the
  // phase never lands in status.completed. Treat it as done once the pipeline
  // has moved past the pause (any status other than paused_osint) and the osint
  // block is present with source=analyst-provided.
  if (
    phaseName === 'osint' &&
    pipelineStatus !== 'paused_osint' &&
    caseData?.osint?.source === 'analyst-provided'
  ) return 'done';
  // When the whole pipeline is paused waiting for analyst OSINT, mark the
  // osint step as 'paused' so it gets a distinct amber icon in the phase bar.
  if (pipelineStatus === 'paused_osint' && phaseName === 'osint') return 'paused';
  if (status.phase === phaseName && KNOWN_PHASES.has(phaseName)) return 'running';
  return 'pending';
}

/* ══════════════════════════════════════════════════════════════════════════
   PHASE VISUALS — one animated SVG scene per phase
   ══════════════════════════════════════════════════════════════════════════ */

/* 1 — Orchestrator: routing hub */
function VisualOrchestrator() {
  return (
    <div className="pv pv--orchestrator">
      <div className="pv-orch__hub">
        <div className="pv-orch__ring pv-orch__ring--1" />
        <div className="pv-orch__ring pv-orch__ring--2" />
        <div className="pv-orch__ring pv-orch__ring--3" />
        <div className="pv-orch__center">
          <svg width="28" height="28" viewBox="0 0 24 24" fill="none">
            <path d="M12 2L4 6v6c0 5.25 3.5 10.15 8 11 4.5-.85 8-5.75 8-11V6L12 2z"
              stroke="#E11D2A" strokeWidth="1.5" fill="rgba(225,29,42,0.15)"/>
            <path d="M9 12l2 2 4-4" stroke="#E11D2A" strokeWidth="1.8" strokeLinecap="round"/>
          </svg>
        </div>
      </div>
      {[0,1,2,3,4,5,6].map(i => (
        <div key={i} className="pv-orch__spoke" style={{ '--i': i }} />
      ))}
      {[0,1,2].map(i => (
        <div key={i} className="pv-orch__packet" style={{ '--i': i }} />
      ))}
      <p className="pv-label">Routing sample through pipeline</p>
    </div>
  );
}

/* 2 — Static Analysis: hex scanner */
function VisualStatic() {
  const rows = Array.from({ length: 9 }, (_, i) =>
    Array.from({ length: 8 }, (_, j) =>
      ((i * 8 + j) * 37 + 0xDEAD).toString(16).toUpperCase().padStart(2,'0')
    ).join(' ')
  );
  return (
    <div className="pv pv--static">
      <div className="pv-hex__code">
        {rows.map((r, i) => (
          <div key={i} className="pv-hex__row" style={{ '--delay': `${i * 0.06}s` }}>
            <span className="pv-hex__addr">{(i * 8).toString(16).padStart(4,'0').toUpperCase()}</span>
            <span className="pv-hex__bytes">{r}</span>
          </div>
        ))}
        <div className="pv-hex__scan-beam" />
        <div className="pv-hex__highlight pv-hex__highlight--1" />
        <div className="pv-hex__highlight pv-hex__highlight--2" />
        <div className="pv-hex__highlight pv-hex__highlight--3" />
      </div>
      <div className="pv-magnifier">
        <svg width="44" height="44" viewBox="0 0 44 44" fill="none">
          <circle cx="18" cy="18" r="12" stroke="#E11D2A" strokeWidth="2" fill="rgba(225,29,42,0.08)"/>
          <line x1="27" y1="27" x2="40" y2="40" stroke="#E11D2A" strokeWidth="2.5" strokeLinecap="round"/>
          <circle cx="18" cy="18" r="7" stroke="rgba(225,29,42,0.3)" strokeWidth="1"/>
        </svg>
      </div>
      <p className="pv-label">Parsing binary structure</p>
    </div>
  );
}

/* 3 — Dynamic Analysis: sandbox detonation */
function VisualDynamic() {
  const nodes = [
    { x: 50, y: 20, label: 'sample.exe' },
    { x: 25, y: 52, label: 'cmd.exe' },
    { x: 75, y: 52, label: 'net.exe' },
    { x: 15, y: 78, label: 'reg.exe' },
    { x: 40, y: 78, label: 'svchost' },
    { x: 85, y: 78, label: 'curl.exe' },
  ];
  const edges = [[0,1],[0,2],[1,3],[1,4],[2,5]];
  return (
    <div className="pv pv--dynamic">
      <svg className="pv-ptree" viewBox="0 0 100 100" preserveAspectRatio="xMidYMid meet">
        {edges.map(([a,b], i) => (
          <line key={i} className="pv-ptree__edge"
            x1={nodes[a].x} y1={nodes[a].y}
            x2={nodes[b].x} y2={nodes[b].y}
            style={{ '--delay': `${i * 0.18}s` }} />
        ))}
        {nodes.map((n, i) => (
          <g key={i} className="pv-ptree__node" style={{ '--delay': `${i * 0.22}s` }}>
            <circle cx={n.x} cy={n.y} r={i === 0 ? 5.5 : 3.5}
              fill={i === 0 ? 'rgba(225,29,42,0.25)' : 'rgba(255,255,255,0.05)'}
              stroke={i === 0 ? '#E11D2A' : 'rgba(255,255,255,0.3)'}
              strokeWidth="0.8"/>
            <text x={n.x} y={n.y + 8} textAnchor="middle"
              fontSize="4.5" fill="rgba(255,255,255,0.5)" fontFamily="JetBrains Mono, monospace">
              {n.label}
            </text>
          </g>
        ))}
      </svg>
      <div className="pv-burst">
        {[0,1,2,3,4,5,6,7].map(i => (
          <div key={i} className="pv-burst__ray" style={{ '--i': i }} />
        ))}
      </div>
      <p className="pv-label">Process tree captured — 6 nodes</p>
    </div>
  );
}

/* 4 — OSINT Research: radar ping */
function VisualOSINT() {
  const hits = [
    { angle: 32,  dist: 58, label: 'VirusTotal' },
    { angle: 125, dist: 45, label: 'MalwareBazaar' },
    { angle: 210, dist: 62, label: 'MISP' },
    { angle: 290, dist: 50, label: 'OTX' },
    { angle: 75,  dist: 38, label: 'Abuse.ch' },
  ];
  return (
    <div className="pv pv--osint">
      <div className="pv-radar">
        <div className="pv-radar__ring pv-radar__ring--1" />
        <div className="pv-radar__ring pv-radar__ring--2" />
        <div className="pv-radar__ring pv-radar__ring--3" />
        <div className="pv-radar__sweep" />
        <div className="pv-radar__cross pv-radar__cross--h" />
        <div className="pv-radar__cross pv-radar__cross--v" />
        {hits.map((h, i) => {
          const rad = (h.angle * Math.PI) / 180;
          const r   = h.dist * 1.1;
          const x   = 50 + r * Math.cos(rad);
          const y   = 50 + r * Math.sin(rad);
          return (
            <div key={i} className="pv-radar__hit"
              style={{ left: `${x}%`, top: `${y}%`, '--delay': `${i * 0.55}s` }}>
              <div className="pv-radar__dot" />
              <span className="pv-radar__hit-label">{h.label}</span>
            </div>
          );
        })}
      </div>
      <p className="pv-label">Querying threat intelligence feeds</p>
    </div>
  );
}

/* 5 — Correlation-Attribution: converging nodes */
function VisualCorrelation() {
  const inputs = [
    { label: 'Static',   angle: -100 },
    { label: 'Dynamic',  angle: -40  },
    { label: 'OSINT',    angle:  20  },
    { label: 'History',  angle:  80  },
    { label: 'Vendor',   angle:  140 },
  ];
  return (
    <div className="pv pv--correlation">
      <div className="pv-correlate">
        {inputs.map((inp, i) => {
          const rad = (inp.angle * Math.PI) / 180;
          const x   = 50 + 38 * Math.cos(rad);
          const y   = 50 + 38 * Math.sin(rad);
          return (
            <div key={i} className="pv-correlate__input"
              style={{ left: `${x}%`, top: `${y}%`, '--delay': `${i * 0.2}s` }}>
              <div className="pv-correlate__node" />
              <span className="pv-correlate__label">{inp.label}</span>
              <div className="pv-correlate__beam"
                style={{
                  '--cx': `${50 - x}%`, '--cy': `${50 - y}%`,
                  '--angle': `${inp.angle + 180}deg`,
                }} />
            </div>
          );
        })}
        <div className="pv-correlate__center">
          <div className="pv-correlate__center-ring" />
          <span className="pv-correlate__center-label">ATT&amp;CK</span>
        </div>
        <div className="pv-mitre">
          {Array.from({ length: 20 }).map((_, i) => (
            <div key={i} className="pv-mitre__cell" style={{ '--delay': `${i * 0.08}s` }} />
          ))}
        </div>
      </div>
      <p className="pv-label">Mapping TTPs — fusing all phases</p>
    </div>
  );
}

/* 6 — Detection Engineering: rule forge */
const YARA_LINES = [
  'rule Malytic_Detect_001 {',
  '  meta:',
  '    author  = "Malytic.AI"',
  '    date    = "2025-06-23"',
  '  strings:',
  '    $s1 = { 4D 5A 90 00 }',
  '    $s2 = "CreateRemoteThread"',
  '    $s3 = /http[s]?:\\/\\/.{4,64}\\.(ru|cn)/',
  '  condition:',
  '    uint16(0)==0x5A4D and any of them',
  '}',
];
function VisualDetection() {
  return (
    <div className="pv pv--detection">
      <div className="pv-rule">
        <div className="pv-rule__header">
          <span className="pv-rule__badge">YARA</span>
          <span className="pv-rule__name">Malytic_Detect_001</span>
        </div>
        <div className="pv-rule__lines">
          {YARA_LINES.map((line, i) => (
            <div key={i} className="pv-rule__line" style={{ '--delay': `${i * 0.12}s` }}>
              <span className="pv-rule__lnum">{String(i+1).padStart(2,'0')}</span>
              <span className="pv-rule__text">{line}</span>
            </div>
          ))}
          <div className="pv-rule__cursor" />
        </div>
      </div>
      <div className="pv-shield">
        {[0,1,2,3].map(i => (
          <div key={i} className="pv-shield__seg" style={{ '--i': i }} />
        ))}
        <svg width="28" height="28" viewBox="0 0 24 24" fill="none">
          <path d="M9 12l2 2 4-4" stroke="#E11D2A" strokeWidth="2" strokeLinecap="round"/>
        </svg>
      </div>
      <p className="pv-label">Generating detection rules</p>
    </div>
  );
}

/* 7 — Report Generation: document render */
function VisualReport() {
  return (
    <div className="pv pv--report">
      <div className="pv-docs">
        <div className="pv-doc pv-doc--back" />
        <div className="pv-doc pv-doc--mid" />
        <div className="pv-doc pv-doc--front">
          <div className="pv-doc__header-bar" />
          <div className="pv-doc__title-line" />
          <div className="pv-doc__sub-line" />
          <div className="pv-doc__section-label" />
          {[0,1,2,3,4,5,6].map(i => (
            <div key={i} className="pv-doc__text-line" style={{
              '--delay': `${i * 0.09}s`,
              width: `${60 + (i % 3) * 12}%`,
            }} />
          ))}
          <div className="pv-doc__section-label pv-doc__section-label--2" />
          {[0,1,2].map(i => (
            <div key={i} className="pv-doc__text-line pv-doc__text-line--short" style={{
              '--delay': `${0.7 + i * 0.1}s`,
              width: `${45 + i * 10}%`,
            }} />
          ))}
        </div>
      </div>
      <div className="pv-pdf-badge">
        <svg width="16" height="16" viewBox="0 0 20 20" fill="none">
          <rect x="3" y="2" width="14" height="17" rx="2" stroke="#E11D2A" strokeWidth="1.5"/>
          <path d="M7 8h6M7 11h6M7 14h4" stroke="#E11D2A" strokeWidth="1.2" strokeLinecap="round"/>
        </svg>
        PDF ready
      </div>
      <p className="pv-label">Rendering executive + technical report</p>
    </div>
  );
}

/* 8 — Elastic Push: data stream */
function VisualElastic() {
  return (
    <div className="pv pv--elastic">
      <div className="pv-stream">
        {[0,1,2,3,4,5,6,7,8].map(i => (
          <div key={i} className="pv-stream__packet" style={{ '--i': i }}>
            <span>{['IOC','RULE','HASH','SIG','TTP','IOC','RULE','HASH','SIG'][i]}</span>
          </div>
        ))}
        <svg className="pv-stream__arrow" height="60" width="2" viewBox="0 0 2 60">
          <line x1="1" y1="0" x2="1" y2="60" stroke="rgba(225,29,42,0.25)" strokeWidth="1" strokeDasharray="3 3"/>
        </svg>
      </div>
      <div className="pv-elastic-node">
        <div className="pv-elastic-node__ring" />
        <svg width="32" height="32" viewBox="0 0 32 32" fill="none">
          <ellipse cx="16" cy="8" rx="10" ry="4" stroke="#E11D2A" strokeWidth="1.5"/>
          <path d="M6 8v8c0 2.2 4.48 4 10 4s10-1.8 10-4V8" stroke="#E11D2A" strokeWidth="1.5"/>
          <path d="M6 16v8c0 2.2 4.48 4 10 4s10-1.8 10-4v-8" stroke="#E11D2A" strokeWidth="1.5"/>
        </svg>
        <span className="pv-elastic-node__label">Elasticsearch</span>
      </div>
      <p className="pv-label">Pushing IOCs + rules to Elastic stack</p>
    </div>
  );
}

/* ── Visual map — keys match backend short phase names ─────────────────── */
const PHASE_VISUAL = {
  static:      <VisualStatic />,
  dynamic:     <VisualDynamic />,
  osint:       <VisualOSINT />,
  correlation: <VisualCorrelation />,
  detection:   <VisualDetection />,
  report:      <VisualReport />,
  elastic:     <VisualElastic />,
};

/* ── Phase step in the pipeline bar ─────────────────────────────────────── */
function PhaseStep({ phaseName, idx, state }) {
  const meta = PHASE_META[phaseName];
  return (
    <div className={`lstep lstep--${state}`} aria-label={`${meta.label}: ${state}`}>
      <div className="lstep__circle">
        {state === 'done' && (
          <svg width="11" height="11" viewBox="0 0 12 12" fill="none">
            <path d="M2.5 6l2.5 2.5 4.5-4.5" stroke="#2FBF71" strokeWidth="1.8" strokeLinecap="round"/>
          </svg>
        )}
        {state === 'failed' && (
          <svg width="10" height="10" viewBox="0 0 12 12" fill="none">
            <path d="M3 3l6 6M9 3l-6 6" stroke="#E11D2A" strokeWidth="1.8" strokeLinecap="round"/>
          </svg>
        )}
        {state === 'running' && <div className="lstep__pulse" />}
        {state === 'paused'  && (
          <svg width="10" height="10" viewBox="0 0 12 12" fill="none">
            <rect x="2" y="2" width="3" height="8" rx="0.8" fill="#f59e0b"/>
            <rect x="7" y="2" width="3" height="8" rx="0.8" fill="#f59e0b"/>
          </svg>
        )}
        {state === 'pending' && <span className="lstep__num">{idx + 1}</span>}
      </div>
      <span className="lstep__label">{meta.label}</span>
    </div>
  );
}

/* ── OSINT pause panel ───────────────────────────────────────────────────── */
function OsintPausePanel({ caseId }) {
  const fileRef = useRef(null);
  const [osintFile, setOsintFile]         = useState(null);
  const [fileError, setFileError]         = useState(null);
  const [resuming, setResuming]           = useState(false);
  const [resumeError, setResumeError]     = useState(null);

  const validate = (f) => {
    if (!f) return;
    const ext = f.name.split('.').pop().toLowerCase();
    if (ext !== 'json') {
      setFileError('Please upload a .json file.');
      setOsintFile(null);
      return;
    }
    setFileError(null);
    setOsintFile(f);
  };

  const handleResume = async () => {
    if (!osintFile || resuming) return;
    setResuming(true);
    setResumeError(null);
    try {
      await resumeWithOsint(caseId, osintFile);
      // Polling in the parent will pick up pipeline_status=running within 3 s.
    } catch (err) {
      setResumeError(err.body || err.message || 'Resume failed — please try again.');
      setResuming(false);
    }
  };

  return (
    <motion.div className="la-osint-panel"
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4, ease: 'easeOut' }}>

      {/* Header */}
      <div className="la-osint-panel__header">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" aria-hidden="true">
          <rect x="6" y="4" width="4" height="16" rx="1.5" fill="#f59e0b"/>
          <rect x="14" y="4" width="4" height="16" rx="1.5" fill="#f59e0b"/>
        </svg>
        <span className="la-osint-panel__title">PAUSED — AWAITING OSINT</span>
      </div>

      <p className="la-osint-panel__body">
        Static and dynamic analysis are complete. Download the intermediate findings,
        run your own OSINT research (private feeds, dark web, internal sources),
        then upload the results to resume correlation, detection, and report generation.
      </p>

      {/* Step 1: Download */}
      <div className="la-osint-panel__step">
        <span className="la-osint-panel__step-num">1</span>
        <div>
          <p className="la-osint-panel__step-label">Download intermediate findings</p>
          <a
            href={intermediateFindingsUrl(caseId)}
            download={`findings-${caseId}.json`}
            className="la-osint-btn la-osint-btn--download"
          >
            <svg width="14" height="14" viewBox="0 0 16 16" fill="none" aria-hidden="true">
              <path d="M8 2v8M5 7l3 3 3-3" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round"/>
              <path d="M2 13h12" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round"/>
            </svg>
            Download Findings JSON
          </a>
        </div>
      </div>

      {/* Step 2: Upload */}
      <div className="la-osint-panel__step">
        <span className="la-osint-panel__step-num">2</span>
        <div className="la-osint-panel__step-upload">
          <p className="la-osint-panel__step-label">Upload your OSINT findings</p>
          <div
            className={`la-osint-dropzone${osintFile ? ' la-osint-dropzone--filled' : ''}`}
            onClick={e => { e.stopPropagation(); fileRef.current?.click(); }}
            onDrop={e => { e.preventDefault(); validate(e.dataTransfer.files?.[0]); }}
            onDragOver={e => e.preventDefault()}
            role="button"
            tabIndex={0}
            aria-label="Upload OSINT findings (.json)"
            onKeyDown={e => e.key === 'Enter' && fileRef.current?.click()}
          >
            <input
              ref={fileRef}
              type="file"
              accept=".json"
              style={{ display: 'none' }}
              onChange={e => validate(e.target.files?.[0])}
            />
            {osintFile ? (
              <span className="la-osint-filename">
                <span className="la-osint-dot la-osint-dot--ok" aria-hidden="true"/>
                <span>{osintFile.name}</span>
                <button
                  type="button"
                  className="la-osint-clear"
                  onClick={ev => { ev.stopPropagation(); setOsintFile(null); setFileError(null); }}
                  aria-label="Remove OSINT file"
                >✕</button>
              </span>
            ) : (
              <span className="la-osint-prompt">
                Drop <code>.json</code> OSINT findings here, or <u>browse</u>
              </span>
            )}
          </div>
          {fileError && <p className="la-osint-error" role="alert">{fileError}</p>}
        </div>
      </div>

      {/* Step 3: Resume */}
      <div className="la-osint-panel__step">
        <span className="la-osint-panel__step-num">3</span>
        <div>
          <p className="la-osint-panel__step-label">Resume the pipeline</p>
          <button
            type="button"
            className="la-osint-btn la-osint-btn--resume"
            onClick={handleResume}
            disabled={!osintFile || !!fileError || resuming}
            aria-disabled={!osintFile || !!fileError || resuming}
          >
            {resuming ? (
              <>
                <span className="la-osint-spinner" aria-hidden="true"/>
                Resuming…
              </>
            ) : (
              <>
                <svg width="14" height="14" viewBox="0 0 16 16" fill="none" aria-hidden="true">
                  <path d="M4 3l9 5-9 5V3z" fill="currentColor"/>
                </svg>
                Resume Pipeline
              </>
            )}
          </button>
          {resumeError && <p className="la-osint-error" role="alert">{resumeError}</p>}
        </div>
      </div>

    </motion.div>
  );
}

/* ── Main page ───────────────────────────────────────────────────────────── */
export function LiveAnalysis() {
  const { caseId } = useParams();
  const navigate   = useNavigate();

  const fetchFn  = useCallback(() => getCase(caseId), [caseId]);
  const stopWhen = useCallback(d => TERMINAL.includes(d?.pipeline_status), []);

  const { data, error, loading } = usePolling(fetchFn, { intervalMs: 3000, stopWhen });

  if (loading && !data) {
    return (
      <div className="la-center">
        <div className="la-spinner" />
        <span className="la-connecting">Connecting to pipeline…</span>
      </div>
    );
  }
  if (error && !data) {
    return (
      <div className="la-center">
        <AlertTriangle size={26} color="#E11D2A" />
        <span style={{ color: '#E11D2A', fontSize: '0.875rem' }}>{error.message}</span>
      </div>
    );
  }

  const pipelineStatus = data?.pipeline_status ?? 'running';
  const status         = data?.data?.status ?? {};
  const sampleName     = data?.data?.sample?.name ?? caseId?.slice(0, 14);
  const isDone         = TERMINAL.includes(pipelineStatus);
  const isSuccess      = pipelineStatus === 'complete';
  const isPaused       = pipelineStatus === 'paused_osint';

  const currentPhase = getCurrentPhase(status, pipelineStatus);
  const currentMeta  = PHASE_META[currentPhase] ?? { label: 'Analyzing…', sub: 'Pipeline initializing' };
  const visual       = PHASE_VISUAL[currentPhase] ?? <VisualStatic />;

  return (
    <div className="la">

      {/* ── Header ───────────────────────────────────────────────────────── */}
      <div className="la-header">
        <div>
          <p className="la-eyebrow">
            {isDone
              ? (isSuccess ? 'ANALYSIS COMPLETE' : 'PIPELINE FAILED')
              : isPaused ? 'PAUSED — AWAITING OSINT'
              : 'ANALYZING'}
          </p>
          <h1 className="la-title">{sampleName}</h1>
          <p className="la-caseid">{caseId}</p>
        </div>
        {isPaused && (
          <div className="la-paused-badge">
            <svg width="10" height="10" viewBox="0 0 12 12" fill="none" aria-hidden="true">
              <rect x="2" y="2" width="3" height="8" rx="0.8" fill="#f59e0b"/>
              <rect x="7" y="2" width="3" height="8" rx="0.8" fill="#f59e0b"/>
            </svg>
            PAUSED
          </div>
        )}
        {!isDone && !isPaused && (
          <div className="la-live-badge">
            <span className="la-live-dot" />
            LIVE
          </div>
        )}
        {isDone && isSuccess && (
          <div className="la-done-badge">
            <svg width="13" height="13" viewBox="0 0 14 14" fill="none">
              <path d="M2.5 7l3 3 6-6" stroke="#2FBF71" strokeWidth="2" strokeLinecap="round"/>
            </svg>
            COMPLETE
          </div>
        )}
      </div>

      {/* ── OSINT pause panel ────────────────────────────────────────────── */}
      {isPaused && <OsintPausePanel caseId={caseId} />}

      {/* ── Phase visual stage ───────────────────────────────────────────── */}
      {!isDone && !isPaused && (
        <div className="la-stage">
          {/* Active phase label — prominent, above the visual */}
          <AnimatePresence mode="wait">
            <motion.div key={`badge-${currentPhase}`} className="la-stage__badge"
              initial={{ opacity: 0, y: -8 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0 }}
              transition={{ duration: 0.3 }}>
              <span className="la-stage__badge-dot" />
              <span className="la-stage__badge-name">{currentMeta.label}</span>
              <span className="la-stage__badge-sep">—</span>
              <span className="la-stage__badge-sub">{currentMeta.sub}</span>
            </motion.div>
          </AnimatePresence>

          <AnimatePresence mode="wait">
            <motion.div key={currentPhase} className="la-stage__visual"
              initial={{ opacity: 0, y: 16 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -12 }}
              transition={{ duration: 0.38, ease: 'easeOut' }}>
              {visual}
            </motion.div>
          </AnimatePresence>
        </div>
      )}

      {/* ── Pipeline steps ───────────────────────────────────────────────── */}
      <div className="la-pipeline" role="list" aria-label="Analysis pipeline progress">
        {PHASE_ORDER.map((p, i) => {
          const caseData = data?.data;
          const state = phaseState(p, status, pipelineStatus, caseData);
          return (
            <div key={p} className="la-pipeline__item" role="listitem">
              <PhaseStep phaseName={p} idx={i} state={state} />
              {i < PHASE_ORDER.length - 1 && (
                <div className={`la-pipeline__connector la-pipeline__connector--${
                  phaseState(PHASE_ORDER[i+1], status, pipelineStatus, caseData) !== 'pending' ? 'lit' : 'dim'
                }`} />
              )}
            </div>
          );
        })}
      </div>

      {/* ── Failures ─────────────────────────────────────────────────────── */}
      {(status.failed ?? []).length > 0 && (
        <div className="la-failures">
          <p className="la-failures__title">
            <AlertTriangle size={14} /> Phase failures
          </p>
          {status.failed.map(f => (
            <div key={f.phase} className="la-failure-row">
              <span className="la-failure-phase">{f.phase}</span>
              <span className="la-failure-msg">{f.error}</span>
            </div>
          ))}
        </div>
      )}

      {/* ── Done CTA ─────────────────────────────────────────────────────── */}
      {isDone && (
        <motion.div className={`la-cta la-cta--${isSuccess ? 'success' : 'partial'}`}
          initial={{ opacity: 0, scale: 0.97 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ duration: 0.5, ease: 'easeOut' }}>
          <div>
            <p className="la-cta__title">
              {isSuccess ? 'Analysis complete' : 'Finished with errors'}
            </p>
            <p className="la-cta__sub">
              {isSuccess
                ? 'Full threat report, IOC tables, and detection rules are ready.'
                : 'Partial results available — some phases encountered errors.'}
            </p>
          </div>
          <div className="la-cta__actions">
            <Link to={`/case/${caseId}`} className="la-cta__btn">
              View full report
              <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
                <path d="M3 8h10M9 4l4 4-4 4" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round"/>
              </svg>
            </Link>
            {isSuccess && (
              <a
                href={iocExportUrl(caseId)}
                download={`ioc-database-${caseId}.json`}
                className="la-cta__btn la-cta__btn--secondary"
                title="Merge this sample's IOCs with your uploaded database and download the combined file"
              >
                Download updated IOC database
                <svg width="14" height="14" viewBox="0 0 16 16" fill="none" aria-hidden="true">
                  <path d="M8 2v8M5 7l3 3 3-3" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round"/>
                  <path d="M2 13h12" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round"/>
                </svg>
              </a>
            )}
          </div>
        </motion.div>
      )}

    </div>
  );
}
