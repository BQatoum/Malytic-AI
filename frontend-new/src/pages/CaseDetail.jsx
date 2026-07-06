import { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import {
  ChevronDown, ChevronRight, Download, ExternalLink,
  AlertTriangle, Shield, Activity, Globe, Link2,
  Terminal, FileText, Image
} from 'lucide-react';
import { getCase, reportPdfUrl, screenshotUrl } from '../api/client';
import { Badge, ScoreBadge } from '../components/ui/Badge';
import { Button } from '../components/ui/Button';
import { Spinner } from '../components/ui/Spinner';
import './CaseDetail.css';

/* ─── Helpers ──────────────────────────────────────────────────────────────── */
function defang(s) {
  if (!s) return s;
  return s.replace(/https?:\/\//g, 'hxxp://').replace(/\./g, '[.]');
}

function Mono({ children, className = '' }) {
  return <code className={`mono cd-mono ${className}`}>{children}</code>;
}

/* ─── Collapsible section ──────────────────────────────────────────────────── */
function Section({ title, icon: Icon, badge, defaultOpen = false, children }) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div className={`cd-section ${open ? 'cd-section--open' : ''}`}>
      <button
        className="cd-section__header"
        onClick={() => setOpen(o => !o)}
        aria-expanded={open}
      >
        <div className="cd-section__title">
          {Icon && <Icon size={15} aria-hidden="true" />}
          <span>{title}</span>
          {badge && <span className="cd-section__badge">{badge}</span>}
        </div>
        {open ? <ChevronDown size={15} aria-hidden="true" /> : <ChevronRight size={15} aria-hidden="true" />}
      </button>
      {open && <div className="cd-section__body">{children}</div>}
    </div>
  );
}

/* ─── IOC table ────────────────────────────────────────────────────────────── */
function IocTable({ iocs = [] }) {
  if (!iocs.length) return <p className="text-muted" style={{fontSize:'0.875rem'}}>No IOCs recorded.</p>;
  return (
    <div className="cd-ioc-table" role="table" aria-label="Indicators of compromise">
      <div className="cd-ioc-header" role="row" aria-hidden="true">
        <span>Type</span><span>Indicator</span><span>Confidence</span><span>Source</span>
      </div>
      {iocs.map((ioc, i) => {
        const val = ioc.indicator ?? ioc.value ?? ioc.ioc ?? '';
        return (
          <div key={i} className="cd-ioc-row" role="row">
            <span role="cell"><Badge variant="default">{ioc.type ?? '?'}</Badge></span>
            <span role="cell"><Mono>{defang(val)}</Mono></span>
            <span role="cell"><span className="text-muted" style={{fontSize:'0.8rem'}}>{ioc.confidence ?? '—'}</span></span>
            <span role="cell"><span className="text-muted" style={{fontSize:'0.8rem'}}>{ioc.source ?? '—'}</span></span>
          </div>
        );
      })}
    </div>
  );
}

/* ─── Detection rules ──────────────────────────────────────────────────────── */
function RuleBlock({ title, rules = [], lang }) {
  if (!rules.length) return null;
  return (
    <div className="cd-rule-block">
      <p className="cd-rule-title">{title}</p>
      {rules.map((r, i) => (
        <pre key={i} className={`cd-rule-pre cd-rule-pre--${lang}`}>
          <code>{typeof r === 'string' ? r : r.rule ?? r.content ?? JSON.stringify(r, null, 2)}</code>
        </pre>
      ))}
    </div>
  );
}

/* ─── Verdict cards ────────────────────────────────────────────────────────── */
function VerdictCard({ label, value, variant, mono }) {
  return (
    <div className="verdict-card">
      <span className="verdict-card__label">{label}</span>
      <span className={`verdict-card__value ${mono ? 'mono' : ''} ${variant ? `text-${variant}` : ''}`}>
        {value || '—'}
      </span>
    </div>
  );
}

/* ─── Screenshots ──────────────────────────────────────────────────────────── */
function Screenshots({ caseId, screenshotAnalysis }) {
  if (!screenshotAnalysis?.include_in_report) return null;
  const frames = screenshotAnalysis.report_frames ?? [];
  if (!frames.length) return null;
  return (
    <div className="cd-screenshots">
      {frames.map((idx, n) => (
        <figure key={idx} className="cd-screenshot">
          <img
            src={screenshotUrl(caseId, idx)}
            alt={`Detonation frame ${n + 1}`}
            className="cd-screenshot__img"
            loading="lazy"
            width={640} height={480}
          />
          <figcaption className="cd-screenshot__caption mono">
            Fig {n + 1}{screenshotAnalysis.caption ? `: ${screenshotAnalysis.caption}` : ''}
          </figcaption>
        </figure>
      ))}
    </div>
  );
}

/* ─── Key-value table for phase data ──────────────────────────────────────── */
function KVTable({ data, skip = [] }) {
  const entries = Object.entries(data ?? {})
    .filter(([k]) => !k.startsWith('_') && !skip.includes(k));
  if (!entries.length) return <p className="text-muted" style={{fontSize:'0.875rem'}}>No data.</p>;
  return (
    <div className="cd-kv">
      {entries.map(([k, v]) => (
        <div key={k} className="cd-kv__row">
          <span className="cd-kv__key mono">{k}</span>
          <span className="cd-kv__val">
            {typeof v === 'object'
              ? <Mono className="cd-kv__json">{JSON.stringify(v, null, 2)}</Mono>
              : String(v)}
          </span>
        </div>
      ))}
    </div>
  );
}

/* ─── Main component ───────────────────────────────────────────────────────── */
export function CaseDetail() {
  const { caseId }      = useParams();
  const navigate        = useNavigate();
  const [caseData, set] = useState(null);
  const [error, setErr] = useState(null);
  const [loading, setL] = useState(true);

  useEffect(() => {
    getCase(caseId)
      .then(d => { set(d); setL(false); })
      .catch(e => { setErr(e); setL(false); });
  }, [caseId]);

  if (loading) return (
    <div className="cd-center"><Spinner size={32} /></div>
  );
  if (error) return (
    <div className="cd-center">
      <AlertTriangle size={28} className="text-failed" />
      <span className="text-failed">{error.message}</span>
    </div>
  );

  const d          = caseData.data ?? {};
  const static_a   = d.static_analysis  ?? {};
  const dynamic_a  = d.dynamic_analysis ?? {};
  const osint_d    = d.osint            ?? {};
  const attr       = d.attribution      ?? {};
  const detection  = d.detection        ?? {};
  const report_b   = d.report           ?? {};
  const status     = d.status           ?? {};

  const family       = attr.family ?? dynamic_a.sandbox_verdict?.family_guess ?? '—';
  const score        = dynamic_a.sandbox_verdict?.score;
  const confidence   = attr.overall_confidence ?? '—';
  const classification = dynamic_a.claude_verdict?.type ?? dynamic_a.sandbox_verdict?.verdict ?? '—';
  const sampleName   = d.sample?.name ?? caseId.slice(0, 16);

  const iocs         = detection.iocs ?? [];
  const yaraRules    = detection.yara_rules ?? [];
  const sigmaRules   = detection.sigma_rules ?? [];
  const suricataRules= detection.suricata_rules ?? [];
  const screenshotA  = dynamic_a.screenshot_analysis;

  const kibanaUrl = d.elastic?.sigma?.per_rule
    ?.find(r => r.kibana_url)?.kibana_url;

  return (
    <div className="cd">
      {/* Header */}
      <div className="cd__header">
        <div className="cd__breadcrumb">
          <button className="cd__back text-muted" onClick={() => navigate('/')}>
            Cases
          </button>
          <ChevronRight size={14} className="text-faint" aria-hidden="true" />
          <span className="mono text-faint" style={{fontSize:'0.8rem'}}>{caseId.slice(0,12)}…</span>
        </div>
        <h1 className="cd__title">{sampleName}</h1>
        <div className="cd__actions">
          <a href={reportPdfUrl(caseId)} target="_blank" rel="noreferrer" download>
            <Button variant="secondary" size="sm">
              <Download size={14} aria-hidden="true" />
              PDF Report
            </Button>
          </a>
          {kibanaUrl && (
            <a href={kibanaUrl} target="_blank" rel="noreferrer">
              <Button variant="ghost" size="sm">
                <ExternalLink size={14} aria-hidden="true" />
                Kibana rules
              </Button>
            </a>
          )}
        </div>
      </div>

      {/* Verdict cards */}
      <div className="cd__verdict-row">
        <VerdictCard label="Family"     value={family} variant="accent" />
        <VerdictCard label="Classification" value={classification} />
        <VerdictCard label="Confidence" value={confidence} />
        <VerdictCard
          label="Pipeline"
          value={<Badge variant={caseData.pipeline_status === 'complete' ? 'done' : 'running'}>
            {caseData.pipeline_status}
          </Badge>}
        />
      </div>

      {/* Phase sections */}
      <div className="cd__sections">

        <Section title="Static Analysis" icon={Shield} defaultOpen>
          <KVTable data={static_a} skip={['iocs','yara_matches','decoded_strings']} />
        </Section>

        <Section title="Dynamic Analysis" icon={Activity}>
          <KVTable data={dynamic_a} skip={['screenshot_analysis','_screenshot_paths','confirmed_iocs']} />
          {screenshotA && (
            <div style={{marginTop: 'var(--sp-6)'}}>
              <p className="cd-subsection-title">
                <Image size={14} aria-hidden="true" />
                Detonation Screenshots
              </p>
              <Screenshots caseId={caseId} screenshotAnalysis={screenshotA} />
            </div>
          )}
        </Section>

        <Section title="OSINT Findings" icon={Globe}>
          <KVTable data={osint_d} />
        </Section>

        <Section title="Correlation & Attribution" icon={Link2}>
          <KVTable data={attr} skip={['mitre_attack','attack_narrative']} />
          {attr.attack_narrative && (
            <div className="cd-narrative">
              <p className="cd-subsection-title">Attack Narrative</p>
              <p style={{fontSize:'0.9rem', lineHeight:1.7}}>{attr.attack_narrative}</p>
            </div>
          )}
          {attr.mitre_attack?.length > 0 && (
            <div style={{marginTop:'var(--sp-5)'}}>
              <p className="cd-subsection-title">MITRE ATT&amp;CK</p>
              <div className="cd-mitre">
                {attr.mitre_attack.map((t, i) => (
                  <div key={i} className="cd-mitre__row">
                    <Mono className="cd-mitre__id">{t.technique_id}</Mono>
                    <span className="cd-mitre__name">{t.technique_name}</span>
                    <Badge variant="default">{t.confidence}</Badge>
                  </div>
                ))}
              </div>
            </div>
          )}
        </Section>

        <Section
          title="Detection"
          icon={Terminal}
          badge={`${iocs.length} IOCs · ${yaraRules.length + sigmaRules.length + suricataRules.length} rules`}
        >
          <p className="cd-subsection-title" style={{marginBottom:'var(--sp-3)'}}>
            Indicators of Compromise
          </p>
          <IocTable iocs={iocs} />

          <div style={{marginTop:'var(--sp-6)'}}>
            <RuleBlock title={`YARA — ${yaraRules.length} rule(s)`}   rules={yaraRules}    lang="yara" />
            <RuleBlock title={`Sigma — ${sigmaRules.length} rule(s)`} rules={sigmaRules}   lang="sigma" />
            <RuleBlock title={`Suricata — ${suricataRules.length} rule(s)`} rules={suricataRules} lang="suricata" />
          </div>
        </Section>

        {report_b.content && (
          <Section title="Report (Markdown)" icon={FileText}>
            <div className="cd-report-md">{report_b.content.slice(0, 4000)}{report_b.content.length > 4000 ? '\n\n[… truncated — download PDF for full report …]' : ''}</div>
          </Section>
        )}

      </div>
    </div>
  );
}
