import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Plus, ChevronRight, AlertTriangle, Clock } from 'lucide-react';
import { listCases } from '../api/client';
import { Badge, ScoreBadge } from '../components/ui/Badge';
import { Button } from '../components/ui/Button';
import { Spinner } from '../components/ui/Spinner';
import './Dashboard.css';

function statusVariant(ps) {
  if (ps === 'complete')     return 'done';
  if (ps === 'failed')       return 'failed';
  if (ps === 'running')      return 'running';
  if (ps === 'paused_osint') return 'paused_osint';
  return 'pending';
}

function formatDate(iso) {
  if (!iso) return '—';
  return new Date(iso).toLocaleDateString('en-US', {
    month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit',
  });
}

function CaseRow({ c, onClick }) {
  const data        = c.data ?? {};
  const attribution = data.attribution ?? {};
  const dynamic     = data.dynamic_analysis ?? {};
  const sandbox     = dynamic.sandbox_verdict ?? {};
  const family      = attribution.family ?? sandbox.family_guess ?? '—';
  const score       = sandbox.score ?? null;
  const classification = sandbox.verdict ?? attribution.verdict_type ?? '—';

  return (
    <button className="case-row" onClick={onClick} aria-label={`Open case ${c.case_id}`}>
      <div className="case-row__status">
        <Badge variant={statusVariant(c.pipeline_status)}>{c.pipeline_status}</Badge>
      </div>
      <div className="case-row__name">
        <span className="case-row__sample">{c.sample_name || c.case_id.slice(0, 8)}</span>
        <span className="case-row__id mono text-faint">{c.case_id.slice(0, 12)}…</span>
      </div>
      <div className="case-row__family">
        {family !== '—' ? (
          <span className="case-row__family-name">{family}</span>
        ) : (
          <span className="text-faint">—</span>
        )}
      </div>
      <div className="case-row__score">
        {score !== null ? <ScoreBadge score={score} /> : <span className="text-faint">—</span>}
      </div>
      <div className="case-row__class">
        <span className="case-row__class-label">{classification}</span>
      </div>
      <div className="case-row__date">
        <Clock size={12} aria-hidden="true" />
        <span>{formatDate(c.created_at)}</span>
      </div>
      <ChevronRight size={16} className="case-row__arrow" aria-hidden="true" />
    </button>
  );
}

function EmptyState({ onAnalyze }) {
  return (
    <div className="empty-state">
      <AlertTriangle size={40} className="empty-state__icon" aria-hidden="true" />
      <h3>No cases yet</h3>
      <p>Upload a sample to start your first analysis.</p>
      <Button onClick={onAnalyze}>
        <Plus size={16} aria-hidden="true" />
        Analyze a sample
      </Button>
    </div>
  );
}

export function Dashboard() {
  const [cases, setCases]   = useState(null);
  const [error, setError]   = useState(null);
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();

  useEffect(() => {
    listCases()
      .then(data => { setCases(data); setLoading(false); })
      .catch(err  => { setError(err); setLoading(false); });
  }, []);

  return (
    <div className="dashboard">
      {/* Page header */}
      <div className="dashboard__header">
        <div>
          <h1>Cases</h1>
          <p className="dashboard__subtitle text-muted">
            {loading ? '' : `${cases?.length ?? 0} analysis records`}
          </p>
        </div>
        <Button onClick={() => navigate('/')}>
          <Plus size={16} aria-hidden="true" />
          New analysis
        </Button>
      </div>

      {/* State: loading */}
      {loading && (
        <div className="dashboard__loading">
          <Spinner size={28} />
          <span className="text-muted">Loading cases…</span>
        </div>
      )}

      {/* State: error */}
      {error && !loading && (
        <div className="dashboard__error card">
          <AlertTriangle size={20} className="text-failed" aria-hidden="true" />
          <span>Failed to load cases: {error.message}. Is the backend running?</span>
        </div>
      )}

      {/* State: empty */}
      {!loading && !error && cases?.length === 0 && (
        <EmptyState onAnalyze={() => navigate('/')} />
      )}

      {/* State: data */}
      {!loading && !error && cases?.length > 0 && (
        <div className="dashboard__table">
          {/* Table header */}
          <div className="case-header" aria-hidden="true">
            <span>Status</span>
            <span>Sample</span>
            <span>Family</span>
            <span>Score</span>
            <span>Classification</span>
            <span>Date</span>
            <span />
          </div>
          {cases.map(c => (
            <CaseRow
              key={c.case_id}
              c={c}
              onClick={() => navigate(
                (c.pipeline_status === 'running' || c.pipeline_status === 'paused_osint')
                  ? `/live/${c.case_id}` : `/case/${c.case_id}`
              )}
            />
          ))}
        </div>
      )}
    </div>
  );
}
