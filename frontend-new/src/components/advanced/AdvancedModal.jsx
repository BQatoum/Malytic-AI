import { useState, useCallback, useRef } from 'react';
import { X } from 'lucide-react';
import './AdvancedModal.css';

// ── IOC file uploader ─────────────────────────────────────────────────────────
function IocUploader({ iocFile, onIocFile, iocError, onIocError }) {
  const ref = useRef(null);

  const validate = useCallback(f => {
    if (!f) return;
    const ext = f.name.split('.').pop().toLowerCase();
    if (ext !== 'csv' && ext !== 'json') {
      onIocError('Please upload a .csv or .json IOC file.');
      return;
    }
    // CSV: accept by extension — the parser handles malformed rows gracefully
    if (ext === 'csv') {
      onIocError(null);
      onIocFile(f);
      return;
    }
    // JSON: must be a non-empty array of objects
    onIocFile(null);
    onIocError(null);
    const reader = new FileReader();
    reader.onload = e => {
      try {
        const parsed = JSON.parse(e.target.result);
        if (!Array.isArray(parsed)) {
          onIocError('IOC JSON must be an array of indicator objects — e.g. [{\"value\":\"1.2.3.4\",\"type\":\"ip\"}]');
          return;
        }
        onIocError(null);
        onIocFile(f);
      } catch (err) {
        onIocError(`Not valid JSON — ${err.message.split(' at ')[0]}.`);
      }
    };
    reader.onerror = () => onIocError('Could not read file.');
    reader.readAsText(f);
  }, [onIocFile, onIocError]);

  const onDrop = useCallback(e => {
    e.preventDefault();
    validate(e.dataTransfer.files?.[0]);
  }, [validate]);

  return (
    <div className="adv-ioc-uploader">
      <div
        className={`adv-ioc-dropzone${iocFile ? ' adv-ioc-dropzone--filled' : ''}`}
        onClick={e => { e.stopPropagation(); ref.current?.click(); }}
        onDrop={onDrop}
        onDragOver={e => e.preventDefault()}
        role="button"
        tabIndex={0}
        aria-label="Upload IOC database file (.csv or .json)"
        onKeyDown={e => e.key === 'Enter' && ref.current?.click()}
      >
        <input
          ref={ref}
          type="file"
          accept=".csv,.json"
          style={{ display: 'none' }}
          onChange={e => validate(e.target.files?.[0])}
        />
        {iocFile ? (
          <span className="adv-ioc-filename">
            <span className="adv-ioc-dot adv-ioc-dot--ok" aria-hidden="true" />
            <span className="adv-ioc-fname-text">{iocFile.name}</span>
            <button
              type="button"
              className="adv-ioc-clear"
              onClick={ev => { ev.stopPropagation(); onIocFile(null); onIocError(null); }}
              aria-label="Remove IOC file"
            >
              <X size={12} aria-hidden="true" />
            </button>
          </span>
        ) : (
          <span className="adv-ioc-prompt">
            Drop <code>.csv</code> or <code>.json</code> here, or <u>browse</u>
          </span>
        )}
      </div>
      {iocError && (
        <p className="adv-ioc-error" role="alert">{iocError}</p>
      )}
    </div>
  );
}

// ── Static findings uploader (.json only) ────────────────────────────────────
function StaticFindingsUploader({ file, onFile, error, onError }) {
  const ref = useRef(null);

  const validate = useCallback(f => {
    if (!f) return;
    const ext = f.name.split('.').pop().toLowerCase();
    if (ext !== 'json') {
      onError('Please upload a .json file.');
      return;
    }
    // Content validation: must be a JSON object (not array/scalar)
    onFile(null);
    onError(null);
    const reader = new FileReader();
    reader.onload = e => {
      try {
        const parsed = JSON.parse(e.target.result);
        if (typeof parsed !== 'object' || Array.isArray(parsed) || parsed === null) {
          onError('Findings file must be a JSON object, not an array or scalar.');
          return;
        }
        onError(null);
        onFile(f);
      } catch (err) {
        onError(`Not valid JSON — ${err.message.split(' at ')[0]}.`);
      }
    };
    reader.onerror = () => onError('Could not read file.');
    reader.readAsText(f);
  }, [onFile, onError]);

  const onDrop = useCallback(e => {
    e.preventDefault();
    validate(e.dataTransfer.files?.[0]);
  }, [validate]);

  return (
    <div className="adv-ioc-uploader">
      <div
        className={`adv-ioc-dropzone${file ? ' adv-ioc-dropzone--filled' : ''}`}
        onClick={e => { e.stopPropagation(); ref.current?.click(); }}
        onDrop={onDrop}
        onDragOver={e => e.preventDefault()}
        role="button"
        tabIndex={0}
        aria-label="Upload static findings file (.json)"
        onKeyDown={e => e.key === 'Enter' && ref.current?.click()}
      >
        <input
          ref={ref}
          type="file"
          accept=".json"
          style={{ display: 'none' }}
          onChange={e => validate(e.target.files?.[0])}
        />
        {file ? (
          <span className="adv-ioc-filename">
            <span className="adv-ioc-dot adv-ioc-dot--ok" aria-hidden="true" />
            <span className="adv-ioc-fname-text">{file.name}</span>
            <button
              type="button"
              className="adv-ioc-clear"
              onClick={ev => { ev.stopPropagation(); onFile(null); onError(null); }}
              aria-label="Remove static findings file"
            >
              <X size={12} aria-hidden="true" />
            </button>
          </span>
        ) : (
          <span className="adv-ioc-prompt">
            Drop <code>.json</code> here, or <u>browse</u>
          </span>
        )}
      </div>
      {error && (
        <p className="adv-ioc-error" role="alert">{error}</p>
      )}
    </div>
  );
}

// ── Dynamic findings uploader (.json only) ────────────────────────────────────
function DynamicFindingsUploader({ file, onFile, error, onError }) {
  const ref = useRef(null);

  const validate = useCallback(f => {
    if (!f) return;
    const ext = f.name.split('.').pop().toLowerCase();
    if (ext !== 'json') {
      onError('Please upload a .json file.');
      return;
    }
    // Content validation: must be a JSON object (not array/scalar)
    onFile(null);
    onError(null);
    const reader = new FileReader();
    reader.onload = e => {
      try {
        const parsed = JSON.parse(e.target.result);
        if (typeof parsed !== 'object' || Array.isArray(parsed) || parsed === null) {
          onError('Findings file must be a JSON object, not an array or scalar.');
          return;
        }
        onError(null);
        onFile(f);
      } catch (err) {
        onError(`Not valid JSON — ${err.message.split(' at ')[0]}.`);
      }
    };
    reader.onerror = () => onError('Could not read file.');
    reader.readAsText(f);
  }, [onFile, onError]);

  const onDrop = useCallback(e => {
    e.preventDefault();
    validate(e.dataTransfer.files?.[0]);
  }, [validate]);

  return (
    <div className="adv-ioc-uploader">
      <div
        className={`adv-ioc-dropzone${file ? ' adv-ioc-dropzone--filled' : ''}`}
        onClick={e => { e.stopPropagation(); ref.current?.click(); }}
        onDrop={onDrop}
        onDragOver={e => e.preventDefault()}
        role="button"
        tabIndex={0}
        aria-label="Upload dynamic findings file (.json)"
        onKeyDown={e => e.key === 'Enter' && ref.current?.click()}
      >
        <input
          ref={ref}
          type="file"
          accept=".json"
          style={{ display: 'none' }}
          onChange={e => validate(e.target.files?.[0])}
        />
        {file ? (
          <span className="adv-ioc-filename">
            <span className="adv-ioc-dot adv-ioc-dot--ok" aria-hidden="true" />
            <span className="adv-ioc-fname-text">{file.name}</span>
            <button
              type="button"
              className="adv-ioc-clear"
              onClick={ev => { ev.stopPropagation(); onFile(null); onError(null); }}
              aria-label="Remove dynamic findings file"
            >
              <X size={12} aria-hidden="true" />
            </button>
          </span>
        ) : (
          <span className="adv-ioc-prompt">
            Drop <code>.json</code> here, or <u>browse</u>
          </span>
        )}
      </div>
      {error && (
        <p className="adv-ioc-error" role="alert">{error}</p>
      )}
    </div>
  );
}

// ── Single advanced option (checkbox + label + optional extra UI) ─────────────
// children (e.g. the IOC uploader) are rendered OUTSIDE the <label> so that
// clicking them never propagates to the label and accidentally toggles the checkbox.
function AdvancedOptionItem({ id, label, description, checked, onToggle, children }) {
  return (
    <div className={`adv-option${checked ? ' adv-option--checked' : ''}`}>
      {/* Clickable header row — only this area toggles the checkbox */}
      <label className="adv-option__header" htmlFor={id}>
        <input
          id={id}
          type="checkbox"
          className="adv-option__checkbox"
          checked={checked}
          onChange={() => onToggle(id)}
        />
        <span className="adv-option__check-box" aria-hidden="true">
          {checked && (
            <svg viewBox="0 0 12 12" fill="none" width="12" height="12">
              <path d="M2 6l3 3 5-5" stroke="#E11D2A" strokeWidth="1.8"
                strokeLinecap="round" strokeLinejoin="round" />
            </svg>
          )}
        </span>
        <span className="adv-option__text">
          <span className="adv-option__label">{label}</span>
          <span className="adv-option__desc">{description}</span>
        </span>
      </label>
      {/* Extra content lives outside the label — clicks here don't reach it */}
      {checked && children && (
        <div className="adv-option__extra">
          {children}
        </div>
      )}
    </div>
  );
}

// ── Advanced options list ─────────────────────────────────────────────────────
function AdvancedOptionsPanel({
  checked, onToggle,
  iocFile, onIocFile, iocError, onIocError,
  staticFindingsFile, onStaticFindingsFile, staticFindingsError, onStaticFindingsError,
  dynamicFindingsFile, onDynamicFindingsFile, dynamicFindingsError, onDynamicFindingsError,
}) {
  return (
    <div className="adv-options-panel">
      <p className="adv-options-label">// SELECT ENRICHMENTS</p>

      {/* ── Feature 1: Internal IOC database ─────────────────────────────── */}
      <AdvancedOptionItem
        id="ioc_db"
        label="Internal IOC database"
        description="Upload your known-attacker IOC database (IPs, domains, hashes) to cross-reference this sample's indicators — detecting repeat adversaries and shared infrastructure. After analysis, the platform gives you back an updated database with this sample's new indicators merged in, so a brand-new attacker's infrastructure is captured for next time."
        checked={!!checked.ioc_db}
        onToggle={onToggle}
      >
        <IocUploader
          iocFile={iocFile}
          onIocFile={onIocFile}
          iocError={iocError}
          onIocError={onIocError}
        />
      </AdvancedOptionItem>

      {/* ── Feature 2: Analyst-provided static findings ───────────────────── */}
      <AdvancedOptionItem
        id="static_findings"
        label="Upload static analysis findings"
        description="Provide your own static analysis findings (.json). The platform will skip its static phase and use yours, then continue with the rest of the pipeline."
        checked={!!checked.static_findings}
        onToggle={onToggle}
      >
        <StaticFindingsUploader
          file={staticFindingsFile}
          onFile={onStaticFindingsFile}
          error={staticFindingsError}
          onError={onStaticFindingsError}
        />
      </AdvancedOptionItem>

      {/* ── Feature 3: Analyst-provided dynamic findings ──────────────────── */}
      <AdvancedOptionItem
        id="dynamic_findings"
        label="Upload dynamic analysis findings"
        description="Provide your own dynamic/sandbox findings (.json) — the platform will skip its detonation and use yours, then complete the rest of the pipeline."
        checked={!!checked.dynamic_findings}
        onToggle={onToggle}
      >
        <DynamicFindingsUploader
          file={dynamicFindingsFile}
          onFile={onDynamicFindingsFile}
          error={dynamicFindingsError}
          onError={onDynamicFindingsError}
        />
      </AdvancedOptionItem>

      {/* ── Feature 4: Pause for analyst OSINT ───────────────────────────── */}
      <AdvancedOptionItem
        id="pause_for_osint"
        label="Pause for analyst OSINT"
        description="Run static + dynamic, then pause before OSINT so you can run your own threat-intel research (private feeds, dark web, internal sources) and upload the findings to resume correlation and reporting."
        checked={!!checked.pause_for_osint}
        onToggle={onToggle}
      />

    </div>
  );
}

// ── Main modal ────────────────────────────────────────────────────────────────
export function AdvancedModal({ file, onCancel, onSubmit }) {
  const [mode, setMode]         = useState(null); // 'default' | 'advanced'
  const [checked, setChecked]   = useState({});
  const [iocFile, setIocFile]   = useState(null);
  const [iocError, setIocError] = useState(null);
  const [staticFindingsFile, setStaticFindingsFile]   = useState(null);
  const [staticFindingsError, setStaticFindingsError] = useState(null);
  const [dynamicFindingsFile, setDynamicFindingsFile]   = useState(null);
  const [dynamicFindingsError, setDynamicFindingsError] = useState(null);

  const toggleOption = id => setChecked(prev => ({ ...prev, [id]: !prev[id] }));

  // static/dynamic findings checkboxes require a file; ioc_db file is optional.
  const staticOk  = !checked.static_findings  || (!!staticFindingsFile  && !staticFindingsError);
  const dynamicOk = !checked.dynamic_findings || (!!dynamicFindingsFile && !dynamicFindingsError);
  const canRun = Boolean(mode) && !iocError && staticOk && dynamicOk;

  const handleRun = () => {
    if (!canRun) return;
    const options = {};
    if (mode === 'advanced') {
      if (checked.ioc_db && iocFile) options.iocFile = iocFile;
      if (checked.static_findings  && staticFindingsFile)  options.staticFindingsFile  = staticFindingsFile;
      if (checked.dynamic_findings && dynamicFindingsFile) options.dynamicFindingsFile = dynamicFindingsFile;
      if (checked.pause_for_osint) options.pauseForOsint = true;
    }
    onSubmit(options);
  };

  const runLabel =
    mode === 'default'   ? 'START ANALYSIS →' :
    mode === 'advanced'  ? 'RUN WITH ENRICHMENTS →' :
                           'SELECT A MODE TO CONTINUE';

  return (
    <div
      className="adv-overlay"
      role="dialog"
      aria-modal="true"
      aria-label="Configure analysis"
    >
      <div className="adv-panel">

        {/* Header */}
        <div className="adv-header">
          <div className="adv-header__left">
            <p className="adv-eyebrow">// ANALYSIS OPTIONS</p>
            <h2 className="adv-title">Configure Analysis</h2>
            <p className="adv-file-tag">
              <span className="adv-file-dot" aria-hidden="true" />
              <span className="adv-file-tag-name">{file.name}</span>
            </p>
          </div>
          <button
            type="button"
            className="adv-close"
            onClick={onCancel}
            aria-label="Cancel and clear file"
          >
            <X size={18} aria-hidden="true" />
          </button>
        </div>

        {/* Mode selector */}
        <div className="adv-modes">
          <button
            type="button"
            className={`adv-mode-card${mode === 'default' ? ' adv-mode-card--active' : ''}`}
            onClick={() => setMode('default')}
            aria-pressed={mode === 'default'}
          >
            <div className="adv-mode-card__icon" aria-hidden="true">
              <svg viewBox="0 0 22 22" fill="none" width="22" height="22">
                <path d="M11 2L4 5.5v5.5c0 4.4 3 8.5 7 9.5 4-1 7-5.1 7-9.5V5.5L11 2z"
                  stroke="currentColor" strokeWidth="1.5" strokeLinejoin="round" />
                <path d="M8 11l2 2 4-4" stroke="currentColor" strokeWidth="1.6"
                  strokeLinecap="round" />
              </svg>
            </div>
            <span className="adv-mode-card__name">Default Analysis</span>
            <span className="adv-mode-card__desc">
              Full 7-phase pipeline with standard settings
            </span>
          </button>

          <button
            type="button"
            className={`adv-mode-card${mode === 'advanced' ? ' adv-mode-card--active' : ''}`}
            onClick={() => setMode('advanced')}
            aria-pressed={mode === 'advanced'}
          >
            <div className="adv-mode-card__icon" aria-hidden="true">
              <svg viewBox="0 0 22 22" fill="none" width="22" height="22">
                <circle cx="11" cy="11" r="8" stroke="currentColor" strokeWidth="1.5" />
                <path d="M7 11h8M11 7v8" stroke="currentColor" strokeWidth="1.5"
                  strokeLinecap="round" />
                <circle cx="7" cy="7" r="1.5" fill="currentColor" opacity="0.45" />
                <circle cx="15" cy="15" r="1.5" fill="currentColor" opacity="0.45" />
              </svg>
            </div>
            <span className="adv-mode-card__name">Advanced Analysis</span>
            <span className="adv-mode-card__desc">
              Enrich with additional context and org data
            </span>
          </button>
        </div>

        {/* Advanced options — only visible in advanced mode */}
        {mode === 'advanced' && (
          <AdvancedOptionsPanel
            checked={checked}
            onToggle={toggleOption}
            iocFile={iocFile}
            onIocFile={setIocFile}
            iocError={iocError}
            onIocError={setIocError}
            staticFindingsFile={staticFindingsFile}
            onStaticFindingsFile={setStaticFindingsFile}
            staticFindingsError={staticFindingsError}
            onStaticFindingsError={setStaticFindingsError}
            dynamicFindingsFile={dynamicFindingsFile}
            onDynamicFindingsFile={setDynamicFindingsFile}
            dynamicFindingsError={dynamicFindingsError}
            onDynamicFindingsError={setDynamicFindingsError}
          />
        )}

        {/* Footer */}
        <div className="adv-footer">
          <button type="button" className="adv-btn-cancel" onClick={onCancel}>
            Cancel
          </button>
          <button
            type="button"
            className={`adv-btn-run${canRun ? '' : ' adv-btn-run--disabled'}`}
            disabled={!canRun}
            onClick={handleRun}
          >
            {runLabel}
          </button>
        </div>

      </div>
    </div>
  );
}
