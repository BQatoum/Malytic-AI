/**
 * PipelineTracker — live phase progress display.
 *
 * Architecture note: each PhaseNode is intentionally self-contained with a
 * `state` prop ('pending' | 'running' | 'done' | 'failed'). When per-phase
 * custom animations are added in a later pass, drop them into PhaseNode
 * without touching the parent data-flow logic.
 */
import { CheckCircle, XCircle, Circle, Loader } from 'lucide-react';
import './PipelineTracker.css';

// Canonical phase order that maps to what the backend reports
const PHASES = [
  { key: 'static',      label: 'Static Analysis',  short: 'Static'      },
  { key: 'dynamic',     label: 'Dynamic Analysis', short: 'Dynamic'     },
  { key: 'osint',       label: 'OSINT Research',   short: 'OSINT'       },
  { key: 'correlation', label: 'Correlation',      short: 'Correlation' },
  { key: 'detection',   label: 'Detection Eng.',   short: 'Detection'   },
  { key: 'report',      label: 'Report Gen.',      short: 'Report'      },
  { key: 'elastic',     label: 'Elastic Push',     short: 'Elastic'     },
];

function phaseState(key, status) {
  if (!status) return 'pending';
  const { completed = [], failed = [], phase } = status;
  if (completed.includes(key)) return 'done';
  if (failed.some(f => f.phase === key)) return 'failed';
  if (phase === key) return 'running';
  return 'pending';
}

function PhaseNode({ phase, state, errorMsg }) {
  return (
    <div
      className={`phase-node phase-node--${state}`}
      role="listitem"
      aria-label={`${phase.label}: ${state}`}
    >
      {/* State icon — slot for per-phase custom animation later */}
      <div className="phase-node__icon" aria-hidden="true">
        {state === 'done'    && <CheckCircle  size={16} />}
        {state === 'failed'  && <XCircle      size={16} />}
        {state === 'running' && <Loader        size={16} className="phase-node__spin" />}
        {state === 'pending' && <Circle        size={16} />}
      </div>

      <div className="phase-node__body">
        <span className="phase-node__label">{phase.short}</span>
        {state === 'failed' && errorMsg && (
          <span className="phase-node__error" title={errorMsg}>
            {errorMsg.slice(0, 60)}{errorMsg.length > 60 ? '…' : ''}
          </span>
        )}
      </div>
    </div>
  );
}

export function PipelineTracker({ status, pipelineStatus }) {
  const isDone   = pipelineStatus === 'complete' || pipelineStatus === 'failed';
  const hasError = (status?.failed ?? []).length > 0;

  const failedMap = Object.fromEntries(
    (status?.failed ?? []).map(f => [f.phase, f.error])
  );

  return (
    <div className="pipeline-tracker">
      <div className="pipeline-tracker__header">
        <span className="pipeline-tracker__title mono">pipeline</span>
        <span className={`pipeline-tracker__pill pipeline-tracker__pill--${
          isDone ? (hasError ? 'failed' : 'done') : 'running'
        }`}>
          {isDone ? (hasError ? 'partial' : 'complete') : (status?.phase ?? 'queued')}
        </span>
      </div>

      <div className="pipeline-tracker__track" role="list" aria-label="Analysis pipeline phases">
        {PHASES.map((phase, i) => {
          const state = phaseState(phase.key, status);
          return (
            <div key={phase.key} className="pipeline-tracker__step">
              <PhaseNode
                phase={phase}
                state={state}
                errorMsg={failedMap[phase.key]}
              />
              {i < PHASES.length - 1 && (
                <div className={`pipeline-tracker__connector pipeline-tracker__connector--${
                  state === 'done' ? 'done' : 'dim'
                }`} aria-hidden="true" />
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
