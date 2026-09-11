import { useEffect, useState } from 'react'
import {
  AlertOctagon,
  AlertTriangle,
  ArrowLeft,
  ArrowUpRight,
  Check,
  CheckCircle2,

  CircleHelp,
  ClipboardCheck,
  FileSearch,
  Inbox,
  Link2,
  LoaderCircle,
  Mail,
  MapPin,
  Monitor,
  Moon,
  Network,
  RefreshCw,
  ScanLine,
  Search,
  Send,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Sun,
  Upload,
  X,
  XCircle,
} from 'lucide-react'

const TABS = [
  ['overview', 'Overview'],
  ['auth', 'Authentication'],
  ['iocs', 'Indicators'],
  ['intel', 'Intelligence'],
  ['geo', 'GeoIP'],
  ['timeline', 'Timeline'],
  ['graph', 'Graph'],
  ['evidence', 'Evidence'],
  ['related', 'Related emails'],
]

const PROGRESS_STEPS = ['Normalize', 'Forensics', 'Intelligence', 'Risk', 'Explain']
const THEME_OPTIONS = [
  { value: 'system', label: 'System', Icon: Monitor },
  { value: 'light', label: 'Light', Icon: Sun },
  { value: 'dark', label: 'Dark', Icon: Moon },
]

function ThemeToggle({ theme, setTheme }) {
  return <div className="theme-toggle" role="group" aria-label="Theme preference">
    {THEME_OPTIONS.map(({ value, label, Icon }) => <button key={value} type="button" className={theme === value ? 'active' : ''} onClick={() => setTheme(value)} aria-pressed={theme === value} title={`${label} theme`}><Icon size={13} /><span>{label}</span></button>)}
  </div>
}

async function api(path, options = {}) {
  const response = await fetch(path, options)
  const contentType = response.headers.get('content-type') || ''
  const payload = contentType.includes('application/json') ? await response.json() : await response.text()
  if (!response.ok) {
    const message = payload?.detail?.error?.message || payload?.detail || 'Request failed'
    const error = new Error(message)
    error.status = response.status
    error.code = payload?.detail?.error?.code
    throw error
  }
  return payload
}

function gmailErrorMessage(error) {
  const messages = {
    GMAIL_OAUTH_DENIED: 'Gmail connection cancelled.',
    GMAIL_OAUTH_STATE_INVALID: 'Unable to connect to Gmail. Please restart the connection.',
    GMAIL_CONNECT_FAILED: 'Unable to connect to Gmail. Check your Google OAuth configuration.',
    GMAIL_NOT_CONFIGURED: 'Unable to connect to Gmail. Check your Google OAuth configuration.',
    GMAIL_PERMISSION_DENIED: 'Gmail read access was not granted.',
    GMAIL_REAUTH_REQUIRED: 'Your Gmail connection is no longer valid. Please reconnect your account.',
    GMAIL_PROVIDER_UNAVAILABLE: 'Unable to fetch Gmail messages right now. Please try again.',
  }
  return messages[error?.code] || error?.message || 'Gmail request failed.'
}

function formatDate(value) {
  if (!value) return 'Unknown date'
  const parsed = new Date(value)
  return Number.isNaN(parsed.getTime()) ? value : parsed.toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })
}

function verdictFromLevel(level) {
  return { LOW: 'SAFE', MEDIUM: 'SUSPICIOUS', HIGH: 'SUSPICIOUS', CRITICAL: 'DANGEROUS' }[level] || 'SUSPICIOUS'
}

function verdictTone(verdict) {
  return {
    SAFE: 'safe',
    SUSPICIOUS: 'suspicious',
    DANGEROUS: 'dangerous',
  }[verdict] || 'neutral'
}


function VerdictPill({ verdict, compact = false }) {
  const Icon = verdict === 'SAFE' ? ShieldCheck : verdict === 'DANGEROUS' ? AlertOctagon : AlertTriangle
  return <span className={`verdict-pill ${verdictTone(verdict)} ${compact ? 'compact' : ''}`}><Icon size={compact ? 13 : 15} />{verdict}</span>
}

function RiskScore({ score, level }) {
  const verdict = verdictFromLevel(level)
  return <div className={`risk-score ${verdictTone(verdict)}`}>
    <span className="risk-score-label">Risk score</span>
    <strong>{Math.round(score || 0)}</strong><span className="risk-score-max">/100</span>
  </div>
}

function Panel({ title, eyebrow, icon: Icon = Shield, action, children, className = '' }) {
  return <section className={`panel ${className}`}>
    {(title || eyebrow || action) && <div className="panel-header">
      <div className="panel-title"><span className="panel-icon"><Icon size={14} /></span><div><span className="eyebrow">{eyebrow}</span>{title && <h2>{title}</h2>}</div></div>
      {action}
    </div>}
    {children}
  </section>
}

function EmptyState({ icon: Icon = Inbox, title, description, action }) {
  return <div className="empty-state"><Icon size={30} /><h3>{title}</h3><p>{description}</p>{action}</div>
}

function Header({ mode, setMode, connection, onConnect, connecting, onRefresh, onDisconnect, onUpload, theme, setTheme }) {
  return <header className="app-header">
    <div className="header-inner">
      <button className="brand" onClick={() => setMode('protection')} aria-label="Open protection mode">
        <span className="brand-mark"><Shield size={19} /></span>
        <span><strong>FORENSIQ</strong><small>AI EMAIL SECURITY</small></span>
      </button>
      <div className="header-controls">
        <div className="mode-switch" role="tablist" aria-label="Application mode">
          <button className={mode === 'protection' ? 'active' : ''} onClick={() => setMode('protection')} role="tab" aria-selected={mode === 'protection'}><ShieldCheck size={14} />Protection</button>
          <button className={mode === 'investigator' ? 'active' : ''} onClick={() => setMode('investigator')} role="tab" aria-selected={mode === 'investigator'}><FileSearch size={14} />Investigator</button>
        </div>
        <ThemeToggle theme={theme} setTheme={setTheme} />
        <button className="icon-button" onClick={onRefresh} title="Refresh mailbox and cases"><RefreshCw size={16} /></button>
        <div className={`connection-chip ${connection?.connected ? 'connected' : ''}`}>
          <span className="status-dot" />
          {connection?.connected ? (connection.demo ? 'DEMO MAILBOX' : 'GMAIL CONNECTED') : 'GMAIL NOT CONNECTED'}
        </div>
        {connection?.connected && <div className="connected-account" aria-label="Connected Gmail account"><span>{connection.demo ? 'DEMO ACCOUNT' : 'CONNECTED GMAIL'}</span><strong>{connection.demo ? 'Synthetic mailbox' : (connection.email_address || connection.account_email)}</strong></div>}
        {!connection?.connected && <button className="button button-primary button-small" onClick={onConnect} disabled={connecting}>{connecting ? <LoaderCircle className="spin" size={15} /> : <Mail size={15} />}Connect Gmail</button>}
        {connection?.connected && <button className="button button-quiet button-small" onClick={onRefresh}><RefreshCw size={14} />Refresh Mail</button>}
        {connection?.connected && <button className="button button-quiet button-small" onClick={onDisconnect}>Disconnect</button>}
        <button className="button button-quiet button-small" onClick={onUpload}><Upload size={15} />Upload .eml</button>
      </div>
    </div>
  </header>
}

function TrustBanner({ connection }) {
  return <div className="trust-banner">
    <div className="trust-icon"><ShieldCheck size={17} /></div>
    <div><strong>{connection?.demo ? 'Demo mailbox is active' : 'Read-only by design'}</strong><p>{connection?.demo ? 'This synthetic mailbox uses the same analysis pipeline as live Gmail, with no external account access.' : 'ForensiQ keeps OAuth tokens server-side. It never asks for Gmail passwords or modifies messages.'}</p></div>
    <div className="trust-tags"><span>PASSIVE LOOKUPS</span><span>NO AUTO-ACTIONS</span><span>EXPLAINABLE</span></div>
  </div>
}

function StatsRow({ dashboard }) {
  const counts = dashboard?.counts || {}
  return <div className="stats-row">
    <div className="stat-card"><span className="stat-icon blue"><Inbox size={17} /></span><div><strong>{dashboard?.total || 0}</strong><span>emails analyzed</span></div></div>
    <div className="stat-card"><span className="stat-icon red"><AlertOctagon size={17} /></span><div><strong>{counts.DANGEROUS || 0}</strong><span>dangerous</span></div></div>
    <div className="stat-card"><span className="stat-icon amber"><AlertTriangle size={17} /></span><div><strong>{counts.SUSPICIOUS || 0}</strong><span>suspicious</span></div></div>
    <div className="stat-card"><span className="stat-icon green"><ShieldCheck size={17} /></span><div><strong>{counts.SAFE || 0}</strong><span>safe</span></div></div>
  </div>
}

function AccountSummary({ connection }) {
  const demo = Boolean(connection?.demo)
  const email = demo ? 'Synthetic mailbox' : (connection?.email_address || connection?.account_email || 'Connected Gmail')
  const detail = demo ? 'No external account connected' : connection?.last_sync_at ? `Last synced ${formatDate(connection.last_sync_at)}` : 'Connected · Ready to scan'
  return <section className={`account-summary ${demo ? 'demo' : ''}`}>
    <div className="account-summary-icon"><Mail size={18} /></div>
    <div className="account-summary-copy"><span className="eyebrow">{demo ? 'DEMO MAILBOX' : 'CONNECTED GMAIL'}</span><strong>{email}</strong><span>{detail}</span></div>
    <div className="account-summary-status"><span className="status-dot" />{demo ? 'Demo mode' : 'Connected'}</div>
  </section>
}

function MailboxLoading() {
  return <div className="mailbox-loading" role="status" aria-live="polite">
    <div className="loading-heading"><span className="skeleton skeleton-kicker" /><span className="skeleton skeleton-title" /><span className="skeleton skeleton-copy" /></div>
    <div className="skeleton-stats">{[1, 2, 3, 4].map(item => <span className="skeleton" key={item} />)}</div>
    <div className="loading-mail-list">{[1, 2, 3].map(item => <div className="loading-mail-row" key={item}><span className="skeleton skeleton-avatar" /><div><span className="skeleton skeleton-line wide" /><span className="skeleton skeleton-line" /></div><span className="skeleton skeleton-badge" /></div>)}</div>
    <p><LoaderCircle className="spin" size={15} />Syncing your mailbox…</p>
  </div>
}

function MailboxCard({ message, analysis, selected, onAnalyze, onOpen, loading }) {
  const verdict = analysis?.verdict || message.risk_hint || 'SUSPICIOUS'
  return <article className={`mail-card ${selected ? 'selected' : ''}`} onClick={() => onOpen(message)} onKeyDown={event => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); onOpen(message) } }} role="button" tabIndex="0" aria-label={`Open email ${message.subject || 'without a subject'}`}>
    <div className="mail-card-top"><span className="mail-source"><span className="mail-unread" />{message.sender || 'Unknown sender'}</span><span className="mail-date">{formatDate(message.date)}</span></div>
    <div className="mail-card-main"><div><h3>{message.subject || '(no subject)'}</h3><p>{message.snippet || 'No preview available.'}</p></div><VerdictPill verdict={verdict} compact /></div>
    <div className="mail-card-footer"><span>{analysis ? `Analyzed · ${Math.round(analysis.risk_score || 0)}/100` : message.demo ? 'Synthetic message' : 'Not analyzed'}</span>{analysis ? <button className="text-button" onClick={event => { event.stopPropagation(); onOpen(message) }}>View result <ArrowUpRight size={13} /></button> : <button className="text-button accent" disabled={loading} onClick={event => { event.stopPropagation(); onAnalyze(message) }}>{loading ? <LoaderCircle className="spin" size={13} /> : <ScanLine size={13} />}Analyze</button>}</div>
  </article>
}

function WhyPanel({ explanation }) {
  const reasons = explanation?.why || []
  return <Panel eyebrow="Progressive disclosure" title="Why this verdict?" icon={CircleHelp}>
    {reasons.length ? <div className="reason-list">{reasons.map(reason => <div className="reason-item" key={`${reason.signal_id}-${reason.title}`}><span className="reason-marker">!</span><div><strong>{reason.title}</strong><p>{reason.explanation}</p><span className="technical-copy">{reason.technical} · evidence {reason.evidence_ids?.join(', ') || 'derived'}</span></div></div>)}</div> : <p className="muted">No material warning signals were produced by the deterministic checks.</p>}
  </Panel>
}

function SafeActions({ actions }) {
  return <Panel eyebrow="Conservative guidance" title="What should I do?" icon={ClipboardCheck}>
    <div className="action-list">{(actions || []).map(item => <div className="action-item" key={item.action}><span className="action-check"><Check size={14} /></span><div><strong>{item.action}</strong><p>{item.reason}</p></div></div>)}</div>
    <p className="action-note"><ShieldCheck size={14} />Recommendations only. ForensiQ never deletes, replies, forwards, or changes Gmail messages.</p>
  </Panel>
}

function ProtectionResult({ report, onInvestigate, onBack, onViewEmail }) {
  const explanation = report?.user_explanation || {}
  const verdict = explanation.verdict || verdictFromLevel(report?.risk_level)
  return <div className="result-layout">
    <button className="back-link" onClick={onBack}><ArrowLeft size={14} />Back to mailbox</button>
    <div className={`verdict-hero ${verdictTone(verdict)}`}>
      <div><span className="eyebrow">Email security verdict</span><div className="verdict-title"><VerdictPill verdict={verdict} /><h1>{explanation.headline || 'Analysis complete'}</h1></div><p className="verdict-subtitle">{report.subject || '(no subject)'}</p><p className="sender-line"><Mail size={14} />{report.sender || 'Unknown sender'} <span>to {report.recipient || 'you'}</span></p></div>
      <RiskScore score={report.risk_score} level={report.risk_level} />
    </div>
    <div className="result-actions"><button className="button button-secondary" onClick={onViewEmail}><Mail size={16} />View email</button><button className="button button-secondary" onClick={onInvestigate}><FileSearch size={16} />Investigate deeper <ArrowUpRight size={14} /></button><span className="case-ref">{report.case_number} · {report.source_type === 'GMAIL_MOCK' ? 'demo Gmail' : report.source_type}</span></div>
    <div className="result-grid"><WhyPanel explanation={explanation} /><SafeActions actions={report.safe_actions} /></div>
    <details className="technical-disclosure"><summary><span>Technical evidence</span><small>Headers, authentication, and provenance</small></summary><div className="disclosure-grid"><div><span>From</span><strong>{report.metadata?.from || report.sender || '—'}</strong></div><div><span>Reply-To</span><strong>{report.metadata?.reply_to || '—'}</strong></div><div><span>Authentication</span><strong>SPF {report.auth?.spf || 'UNKNOWN'} · DKIM {report.auth?.dkim || 'UNKNOWN'} · DMARC {report.auth?.dmarc || 'UNKNOWN'}</strong></div><div><span>Evidence</span><strong className="mono">{report.original_evidence_hash || report.source_message_id || '—'}</strong></div></div></details>
    <div className="result-footnote"><Sparkles size={14} /><span>{report.ai_explanation?.is_fallback ? 'Explanation generated from deterministic evidence. AI is advisory and cannot change this score.' : 'AI explanation is constrained to verified evidence and cannot change the deterministic score.'}</span></div>
  </div>
}

function EmailPreview({ report, onClose }) {
  return <div className="modal-backdrop" role="presentation" onClick={onClose}><div className="email-modal" role="dialog" aria-modal="true" aria-label="Email preview" onClick={event => event.stopPropagation()}><div className="modal-header"><div><span className="eyebrow">Read-only preview</span><h2>{report.subject || '(no subject)'}</h2></div><button className="icon-button" onClick={onClose} aria-label="Close preview"><X size={18} /></button></div><div className="email-headers"><span>From</span><strong>{report.sender || 'Unknown sender'}</strong><span>To</span><strong>{report.recipient || 'Unknown recipient'}</strong><span>Date</span><strong>{report.metadata?.date || 'Unknown date'}</strong></div><pre className="email-body">{report.parsed?.body_text || 'No text body was extracted.'}</pre><p className="privacy-note"><ShieldCheck size={14} />HTML is not rendered in this preview. Links are never visited by ForensiQ.</p></div></div>
}

function GraphPanel({ graph }) {
  const [selected, setSelected] = useState(null)
  const nodes = graph?.nodes || []
  const edges = graph?.edges || []
  const positions = nodes.reduce((result, node, index) => {
    result[node.id] = { x: 110 + (index % 4) * 190, y: 60 + Math.floor(index / 4) * 115 }
    return result
  }, {})
  const selectedNode = nodes.find(node => node.id === selected)
  return <div className="graph-layout"><div className="graph-canvas">{nodes.length ? <svg viewBox="0 0 880 500" role="img" aria-label="Case investigation graph">
    {edges.map(edge => { const source = positions[edge.source]; const target = positions[edge.target]; if (!source || !target) return null; return <g key={edge.id}><line x1={source.x} y1={source.y} x2={target.x} y2={target.y} /><text x={(source.x + target.x) / 2} y={(source.y + target.y) / 2 - 6}>{edge.type}</text></g> })}
    {nodes.map(node => { const point = positions[node.id]; const active = node.id === selected; return <g className="graph-node" key={node.id} onClick={() => setSelected(node.id)} role="button" tabIndex="0" onKeyDown={event => event.key === 'Enter' && setSelected(node.id)}><rect x={point.x - 66} y={point.y - 24} width="132" height="48" rx="8" className={`${active ? 'active' : ''} ${node.risk_tag === 'MALICIOUS' ? 'malicious' : ''}`} /><text x={point.x} y={point.y - 5} className="node-type">{node.type}</text><text x={point.x} y={point.y + 12} className="node-label">{String(node.label).slice(0, 21)}</text></g> })}
  </svg> : <EmptyState title="No graph entities" description="The current message did not produce graph relationships." />}</div><div className="entity-card"><span className="eyebrow">Selected entity</span>{selectedNode ? <><h3>{selectedNode.type}</h3><p>{selectedNode.label}</p><span className="technical-copy">{selectedNode.provenance || 'OBSERVED'}</span>{selectedNode.metadata && <pre>{JSON.stringify(selectedNode.metadata, null, 2)}</pre>}</> : <p className="muted">Select a node to inspect its evidence and provenance.</p>}</div></div>
}

function Investigator({ report, related, tab, setTab, onBack }) {
  const risk = report?.risk_assessment || {}
  const iocs = report?.iocs?.items || []
  const intel = report?.intel_results || []
  const geo = report?.geoip_list || []
  return <div className="investigator-view">
    <div className="investigator-heading"><button className="back-link" onClick={onBack}><ArrowLeft size={14} />Protection mode</button><div><span className="eyebrow">Deep investigation</span><h1>{report?.subject || 'Case investigation'}</h1><p>{report?.case_number} · {report?.sender || 'Unknown sender'} · {formatDate(report?.created_at)}</p></div><div className="investigator-score"><VerdictPill verdict={verdictFromLevel(report?.risk_level)} compact /><strong>{Math.round(report?.risk_score || 0)}<small>/100</small></strong></div></div>
    <div className="investigator-tabs" role="tablist">{TABS.map(([id, label]) => <button key={id} className={tab === id ? 'active' : ''} onClick={() => setTab(id)} role="tab" aria-selected={tab === id}>{label}{id === 'related' && related?.clusters?.length ? <span className="tab-count">{related.clusters.length}</span> : null}</button>)}</div>
    {tab === 'overview' && <div className="investigator-grid"><Panel eyebrow="Deterministic result" title="Risk assessment" icon={ShieldAlert}><div className="investigator-risk"><RiskScore score={report?.risk_score} level={report?.risk_level} /><div><p>{report?.user_explanation?.headline}</p><span className="technical-copy">Engine {risk.engine_version} · confidence {Math.round((risk.confidence || 0) * 100)}%</span></div></div><div className="signal-list">{(risk.signals || []).map(signal => <div className="signal-row" key={signal.signal_id}><div><strong>{signal.signal_id}</strong><p>{signal.description}</p></div><span>+{signal.weight}</span></div>)}</div></Panel><Panel eyebrow="AI analyst" title="Evidence-bounded interpretation" icon={Sparkles}><div className="ai-state"><VerdictPill verdict={report?.ai_explanation?.classification === 'BENIGN' ? 'SAFE' : 'SUSPICIOUS'} compact /><span>{report?.ai_explanation?.is_fallback ? 'Deterministic fallback' : 'AI interpretation'}</span></div><p className="long-copy">{report?.ai_explanation?.summary}</p><p className="muted">{report?.ai_explanation?.analyst_reasoning}</p><div className="citation-list">{(report?.ai_explanation?.suspicious_indicators || []).map(item => <span key={`${item.evidence_id}-${item.indicator}`}>[{item.evidence_id}] {item.indicator}</span>)}</div></Panel><Panel eyebrow="Observed message" title="Headers and attachments" icon={Mail}><div className="metadata-grid"><div><span>From</span><strong>{report?.metadata?.from || '—'}</strong></div><div><span>Reply-To</span><strong>{report?.metadata?.reply_to || '—'}</strong></div><div><span>Return-Path</span><strong>{report?.metadata?.return_path || '—'}</strong></div><div><span>Mail servers</span><strong>{report?.metadata?.mail_servers?.join(', ') || '—'}</strong></div></div><div className="attachment-list">{(report?.parsed?.attachments || []).length ? report.parsed.attachments.map(item => <div key={item.sha256}><Link2 size={14} /><span>{item.filename}</span><small>{item.sha256?.slice(0, 16)}…</small></div>) : <span className="muted">No attachment metadata observed.</span>}</div></Panel></div>}
    {tab === 'auth' && <Panel eyebrow="Observed headers" title="Authentication and sender identity" icon={ShieldCheck}><div className="auth-grid">{['spf', 'dkim', 'dmarc'].map(name => <div className="auth-card" key={name}><span>{name}</span><strong className={report?.auth?.[name] === 'PASS' ? 'pass' : report?.auth?.[name] === 'FAIL' ? 'fail' : ''}>{report?.auth?.[name] || 'UNKNOWN'}</strong><small>Authentication-Results</small></div>)}</div><div className="metadata-grid wide"><div><span>From</span><strong>{report?.metadata?.from || '—'}</strong></div><div><span>Reply-To</span><strong>{report?.metadata?.reply_to || '—'}</strong></div><div><span>Return-Path</span><strong>{report?.metadata?.return_path || '—'}</strong></div><div><span>Message-ID</span><strong>{report?.metadata?.message_id || '—'}</strong></div></div><div className="contradiction-box"><AlertTriangle size={16} /><div><strong>Trust contradiction analysis</strong><p>{report?.contradictions?.[0]?.explanation || 'No sender identity contradiction was detected.'}</p></div></div></Panel>}
    {tab === 'iocs' && <Panel eyebrow="Observed indicators" title={`${iocs.length} extracted indicators`} icon={Link2}>{iocs.length ? <div className="table-wrap"><table><thead><tr><th>Type</th><th>Value</th><th>Source</th><th>Evidence</th></tr></thead><tbody>{iocs.map(item => <tr key={item.ioc_id}><td className="accent-text">{item.type}</td><td className="mono break">{item.normalized_value}</td><td>{item.source}</td><td className="mono muted">{item.ioc_id}</td></tr>)}</tbody></table></div> : <EmptyState title="No indicators extracted" description="No supported IP, domain, URL, email, or hash was observed." />}</Panel>}
    {tab === 'intel' && <Panel eyebrow="External processing" title="Passive threat intelligence" icon={Search}><p className="section-note">External results are labeled separately from local observations. URLs from the message are not fetched.</p>{intel.length ? <div className="intel-grid">{intel.map(item => <div className="intel-card" key={`${item.provider}-${item.ioc_id}`}><div><strong>{item.provider}</strong><Status status={item.status} /></div><p>{item.result_summary}</p><span>{item.query_type}: {item.query_value}</span></div>)}</div> : <EmptyState title="No intelligence results" description="No indicator enrichment was returned." />}</Panel>}
    {tab === 'geo' && <Panel eyebrow="External processing" title="Observed infrastructure geography" icon={MapPin}><p className="section-note">Approximate infrastructure geography is not an attacker location.</p>{geo.length ? <div className="intel-grid">{geo.map(item => <div className="intel-card" key={item.ip}><div><strong className="mono">{item.ip}</strong><Status status={item.status} /></div><p>{item.city || 'Unknown city'}, {item.country || 'Unknown country'}</p><span>{item.isp || 'Unknown ISP'} · {item.asn || 'ASN unavailable'}</span></div>)}</div> : <EmptyState title="No public infrastructure" description="No public source IP was available for geolocation." />}</Panel>}
    {tab === 'timeline' && <Panel eyebrow="Observed routing" title="Forensic timeline" icon={Send}>{report?.forensic_timeline?.length ? <div className="timeline">{report.forensic_timeline.map((hop, index) => <div className="timeline-item" key={hop.hop_number}><div className="timeline-marker"><span />{index < report.forensic_timeline.length - 1 && <i />}</div><div className="timeline-card"><div><strong>HOP {hop.hop_number} · {hop.by_server}</strong><time>{hop.timestamp || 'Timestamp unavailable'}</time></div><p>From {hop.from_server} via {hop.protocol || 'unknown protocol'}</p><span>{hop.ip || 'No observed IP'} · {hop.for_recipient || 'recipient not recorded'}</span>{hop.anomalies?.length ? <em>{hop.anomalies.join(', ')}</em> : null}</div></div>)}</div> : <EmptyState title="No routing trail" description="The message did not contain Received headers." />}</Panel>}
    {tab === 'graph' && <Panel eyebrow="Derived relationships" title="Investigation graph" icon={Network}><GraphPanel graph={report?.graph} /></Panel>}
    {tab === 'evidence' && <Panel eyebrow="Integrity and provenance" title="Evidence record" icon={ClipboardCheck}><div className="evidence-grid"><div><span>Evidence hash</span><strong className="mono">{report?.original_evidence_hash}</strong></div><div><span>Source</span><strong>{report?.source_type} · {report?.source_message_id}</strong></div><div><span>Analysis provenance</span><strong>Local observation → passive enrichment → derived risk</strong></div><div><span>AI policy</span><strong>Email content is untrusted data, never instructions</strong></div></div></Panel>}
    {tab === 'related' && <Panel eyebrow="Cross-email correlation" title="Potential related email clusters" icon={Network}>{related?.clusters?.length ? related.clusters.map(cluster => <div className="cluster-card" key={cluster.cluster_id}><div><VerdictPill verdict="SUSPICIOUS" compact /><strong>{cluster.label}</strong></div><p>{cluster.message_count} messages · {Math.round(cluster.confidence * 100)}% confidence</p><div className="cluster-indicators">{cluster.shared_indicators.map(item => <span key={`${item.type}-${item.normalized_value}`}>{item.type}: {item.value}</span>)}</div><small>Affected recipients: {cluster.affected_recipients?.join(', ') || 'not available'}</small></div>) : <EmptyState title="No related email cluster" description="Analyze more Gmail messages to find shared domains, URLs, IPs, senders, ASNs, or attachment hashes." />}</Panel>}
  </div>
}

function Status({ status }) {
  return <span className={`status-label ${String(status).toLowerCase()}`}>{status || 'UNKNOWN'}</span>
}

function Mailbox({ connection, messages, cases, selectedMessage, setSelectedMessage, onAnalyze, onScan, scanLimit, setScanLimit, loadingMessage, scanning, onConnect, connecting, onUpload, error, loadingMailbox }) {
  const caseByMessage = Object.fromEntries(cases.map(item => [item.source_message_id, item]))
  if (loadingMailbox && !connection) return <MailboxLoading />
  return <>
    <div className="page-heading"><div><span className="eyebrow">Protection</span><h1>Your inbox, protected.</h1><p>Understand suspicious emails before they become incidents.</p></div><div className="heading-actions"><select value={scanLimit} onChange={event => setScanLimit(Number(event.target.value))} aria-label="Scan size"><option value="10">Scan 10</option><option value="25">Scan 25</option><option value="50">Scan 50</option></select><button className="button button-primary" onClick={onScan} disabled={!connection?.connected || scanning}>{scanning ? <LoaderCircle className="spin" size={16} /> : <ScanLine size={16} />}{scanning ? 'Scanning…' : 'Scan recent emails'}</button></div></div>
    {error && <div className="error-banner"><XCircle size={16} />{error}<button onClick={() => window.location.reload()}><X size={14} /></button></div>}
    {!connection?.connected ? <div className="connect-layout"><Panel eyebrow="Start with your mailbox" title="Connect Gmail without sharing your password" icon={Mail} className="connect-card"><p>ForensiQ requests read-only mailbox access through Google's OAuth flow. Tokens stay on the server and Gmail messages are analyzed only when you select or scan them.</p><div className="connect-points"><span><CheckCircle2 size={15} />Read-only scope</span><span><CheckCircle2 size={15} />No automatic deletion</span><span><CheckCircle2 size={15} />Same pipeline as .eml</span></div><button className="button button-primary" onClick={onConnect} disabled={connecting}>{connecting ? <LoaderCircle className="spin" size={16} /> : <Mail size={16} />}{connecting ? 'Connecting…' : 'Continue with Google'}</button><span className="technical-copy connect-security-note"><ShieldCheck size={13} /> No Gmail password needed</span></Panel><Panel eyebrow="No Gmail? No problem" title="Upload an email file" icon={Upload} className="connect-card muted-card"><p>Drop an RFC822 `.eml` message for the same normalization, forensics, risk, and investigation workflow.</p><button className="button button-secondary" onClick={onUpload}><Upload size={16} />Choose .eml file</button><span className="technical-copy">Files stay local in this demo environment.</span></Panel></div> : <>
      <AccountSummary connection={connection} />
      <StatsRow dashboard={{ total: cases.length, counts: cases.reduce((result, item) => { result[item.verdict] = (result[item.verdict] || 0) + 1; return result }, {}) }} />
      <div className="mailbox-layout"><Panel eyebrow="Recent and relevant" title={connection.demo ? 'DEMO MAILBOX' : 'Recent emails'} icon={Inbox} action={<span className="panel-count">{messages.length} messages</span>} className="mailbox-panel"><div className="mail-list">{messages.length ? messages.map(message => <MailboxCard key={message.message_id} message={message} analysis={caseByMessage[message.message_id]} selected={selectedMessage?.message_id === message.message_id} onAnalyze={onAnalyze} onOpen={setSelectedMessage} loading={loadingMessage === message.message_id} />) : <EmptyState title="No recent messages" description="Your mailbox returned no messages in the selected window." action={<button className="button button-secondary" onClick={onScan} disabled={scanning}><RefreshCw size={15} />Scan again</button>} />}</div></Panel><Panel eyebrow="Your protection loop" title="A safer reading habit" icon={ShieldCheck} className="habit-panel"><div className="habit-step"><span>01</span><div><strong>See the verdict first</strong><p>Safe, suspicious, or dangerous — before technical detail.</p></div></div><div className="habit-step"><span>02</span><div><strong>Ask why</strong><p>Every important signal is tied to observable evidence.</p></div></div><div className="habit-step"><span>03</span><div><strong>Choose a safe action</strong><p>Recommendations never mutate your mailbox for you.</p></div></div><div className="scan-control"><span>Scan scope</span><strong>{scanLimit} recent messages</strong><button className="text-button accent" onClick={onScan} disabled={!connection?.connected || scanning}><RefreshCw size={13} />{scanning ? 'Scanning…' : 'Run scan'}</button></div></Panel></div>
    </>}
  </>
}

export default function App() {
  const [mode, setMode] = useState('protection')
  const [theme, setTheme] = useState(() => window.localStorage.getItem('forensiq-theme') || 'system')
  const [connection, setConnection] = useState(null)
  const [messages, setMessages] = useState([])
  const [cases, setCases] = useState([])

  const [selectedMessage, setSelectedMessage] = useState(null)
  const [report, setReport] = useState(null)
  const [related, setRelated] = useState(null)
  const [investigatorTab, setInvestigatorTab] = useState('overview')
  const [connecting, setConnecting] = useState(false)
  const [loadingMessage, setLoadingMessage] = useState('')
  const [scanning, setScanning] = useState(false)
  const [scanLimit, setScanLimit] = useState(10)
  const [progressStep, setProgressStep] = useState(-1)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [showEmail, setShowEmail] = useState(false)
  const [fileInputKey, setFileInputKey] = useState(0)
  const [loadingMailbox, setLoadingMailbox] = useState(true)

  useEffect(() => {
    document.documentElement.dataset.theme = theme
    window.localStorage.setItem('forensiq-theme', theme)
  }, [theme])

  const refresh = async () => {
    setError('')
    setLoadingMailbox(true)
    try {
      const [status, dash] = await Promise.all([api('/api/v1/gmail/status'), api('/api/v1/dashboard')])
      setConnection(status)

      setCases(dash.cases || [])
      if (status.connected) {
        const mailbox = await api('/api/v1/gmail/messages?limit=50')
        setMessages(mailbox.messages || [])
      } else setMessages([])
    } catch (requestError) {
      if (requestError.code === 'GMAIL_REAUTH_REQUIRED') {
        setConnection(previous => previous ? { ...previous, connected: false, status: 'reauth_required' } : previous)
      }
      setError(gmailErrorMessage(requestError))
    } finally { setLoadingMailbox(false) }
  }

  // Initial API synchronization is intentional: status and mailbox state are external data.
  useEffect(() => {
    const params = new URLSearchParams(window.location.search)
    const gmailResult = params.get('gmail')
    const gmailError = params.get('gmail_error')
    // eslint-disable-next-line react/set-state-in-effect
    if (gmailResult === 'connected') setNotice('Gmail connected. Loading your recent messages.')
    if (gmailResult === 'error') setError(gmailErrorMessage({ code: gmailError }))
    if (gmailResult) window.history.replaceState({}, document.title, window.location.pathname)
    refresh()
  }, [])

  const loadReport = async caseId => {
    const detail = await api(`/api/v1/cases/${caseId}`)
    setReport(detail.case)
    try { setRelated(await api(`/api/v1/cases/${caseId}/related`)) } catch { setRelated(null) }
  }

  const connect = async () => {
    setConnecting(true)
    setError('')
    try {
      const result = await api('/api/v1/gmail/connect', { method: 'POST' })
      if (result.authorization_url) {
        setNotice('Live Gmail is configured. Redirecting to Google for read-only access.')
        window.location.assign(result.authorization_url)
      } else {
        setConnection(result)
        const mailbox = await api('/api/v1/gmail/messages?limit=50')
        setMessages(mailbox.messages || [])
        setNotice(result.demo ? 'Demo mailbox connected. These synthetic messages use the production analysis path.' : 'Gmail connected.')
      }
    } catch (requestError) {
      setError(gmailErrorMessage(requestError))
    } finally { setConnecting(false) }
  }

  const disconnect = async () => {
    setError('')
    try {
      await api('/api/v1/gmail/disconnect', { method: 'POST' })
      setConnection({ connected: false, mode: 'live', demo: false, status: 'disconnected' })
      setMessages([])
      setReport(null)
      setSelectedMessage(null)
      setNotice('Gmail disconnected.')
    } catch (requestError) {
      setError(gmailErrorMessage(requestError))
    }
  }

  const analyzeMessage = async message => {
    setLoadingMessage(message.message_id)
    setError('')
    setProgressStep(0)
    try {
      setProgressStep(2)
      const summary = await api(`/api/v1/gmail/messages/${encodeURIComponent(message.message_id)}/analyze`, { method: 'POST' })
      setProgressStep(4)
      await loadReport(summary.case_id)
      setSelectedMessage(message)
      setNotice('Analysis complete. The verdict is based on deterministic evidence.')
      await refresh()
    } catch (requestError) { setError(gmailErrorMessage(requestError)) }
    finally { setLoadingMessage(''); setProgressStep(-1) }
  }

  const scan = async () => {
    setScanning(true); setError(''); setProgressStep(0)
    try {
      const result = await api('/api/v1/gmail/scan', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ limit: scanLimit }) })
      setProgressStep(4)
      await refresh()
      if (result.cases?.[0]) await loadReport(result.cases[0].case_id)
      setNotice(`${result.analyzed_count} new message${result.analyzed_count === 1 ? '' : 's'} analyzed${result.reused_count ? ` · ${result.reused_count} already known` : ''}.`)
    } catch (requestError) { setError(gmailErrorMessage(requestError)) }
    finally { setScanning(false); setProgressStep(-1) }
  }

  const handleUpload = file => {
    if (!file) return
    setError(''); setProgressStep(0)
    const formData = new FormData(); formData.append('file', file)
    api('/api/v1/analyze', { method: 'POST', body: formData }).then(async summary => {
      setProgressStep(4); await loadReport(summary.case_id); setMode('protection'); setNotice('Local .eml analyzed through the same ForensiQ pipeline.')
      await refresh()
    }).catch(requestError => setError(gmailErrorMessage(requestError))).finally(() => { setProgressStep(-1); setFileInputKey(value => value + 1) })
  }

  const openMessage = message => {
    setSelectedMessage(message)
    const existing = cases.find(item => item.source_message_id === message.message_id)
    if (existing) loadReport(existing.case_id).catch(requestError => setError(gmailErrorMessage(requestError)))
    else analyzeMessage(message)
  }

  const openCase = summary => {
    loadReport(summary.case_id).then(() => setMode('investigator')).catch(requestError => setError(gmailErrorMessage(requestError)))
  }

  return <div className="app-shell">
    <Header mode={mode} setMode={setMode} connection={connection} onConnect={connect} connecting={connecting} onRefresh={refresh} onDisconnect={disconnect} onUpload={() => document.querySelector('.hidden-upload')?.click()} theme={theme} setTheme={setTheme} />
    <input className="hidden-upload" key={`global-${fileInputKey}`} type="file" accept=".eml,message/rfc822,text/plain" onChange={event => handleUpload(event.target.files?.[0])} aria-label="Upload email file" />
    <main className="page-shell">
      <TrustBanner connection={connection} />
      {notice && <div className="notice-banner"><CheckCircle2 size={16} />{notice}<button onClick={() => setNotice('')}><X size={14} /></button></div>}
      {progressStep >= 0 && <div className="progress-bar">{PROGRESS_STEPS.map((step, index) => <span className={index <= progressStep ? 'active' : ''} key={step}>{index < progressStep ? <Check size={12} /> : <span className="progress-dot" />}{step}</span>)}</div>}
      {mode === 'protection' && <Mailbox connection={connection} messages={messages} cases={cases} selectedMessage={selectedMessage} setSelectedMessage={openMessage} onAnalyze={analyzeMessage} onScan={scan} scanLimit={scanLimit} setScanLimit={setScanLimit} loadingMessage={loadingMessage} scanning={scanning} onConnect={connect} connecting={connecting} onUpload={() => document.querySelector('.hidden-upload')?.click()} error={error} loadingMailbox={loadingMailbox} />}
      {mode === 'protection' && report && <ProtectionResult report={report} onInvestigate={() => { setMode('investigator'); setInvestigatorTab('overview') }} onBack={() => setReport(null)} onViewEmail={() => setShowEmail(true)} />}
      {mode === 'investigator' && (report ? <Investigator report={report} related={related} tab={investigatorTab} setTab={setInvestigatorTab} onBack={() => setMode('protection')} /> : <Panel eyebrow="Case library" title="Choose an investigation" icon={FileSearch}><div className="case-library">{cases.length ? cases.map(item => <button key={item.case_id} onClick={() => openCase(item)}><div><VerdictPill verdict={item.verdict || verdictFromLevel(item.risk_level)} compact /><strong>{item.subject || '(no subject)'}</strong><span>{item.sender}</span></div><div><b>{Math.round(item.risk_score || 0)}</b><small>{formatDate(item.created_at)}</small></div></button>) : <EmptyState title="No cases yet" description="Analyze a Gmail message or upload an .eml to create a case." />}</div></Panel>)}
    </main>
    {showEmail && report && <EmailPreview report={report} onClose={() => setShowEmail(false)} />}
    <footer className="app-footer"><span><Shield size={13} />ForensiQ keeps observation, enrichment, and AI interpretation visibly separate.</span><span>Read-only by design</span></footer>
  </div>
}
