import { ExternalLink, Globe2, Loader2, Radar, SearchCheck, ShieldQuestion } from 'lucide-react';
import { useState } from 'react';

function OsintSection({ result, manualOsint, manualLoading, manualError, onManualScan }) {
  const [manualText, setManualText] = useState('');
  const osint = manualOsint || result?.osint;
  const risk = osint?.risk || { score: 0, level: 'pending', reasons: [] };
  const evidence = osint?.evidence || [];
  const domains = osint?.domain_intelligence || [];
  const searchUrls = osint?.search_urls || {};
  const sourceStatus = osint?.source_status || [];
  const investigationMode = manualOsint ? 'Manual' : result?.osint_triggered ? 'Triggered' : 'Waiting';

  return (
    <section className="workspace-section" id="osint">
      <div className="section-heading">
        <p className="eyebrow">OSINT Intelligence</p>
        <h2>Public Evidence</h2>
      </div>

      <div className="osint-summary">
        <div>
          <Radar size={22} />
          <span>{investigationMode}</span>
          <p>Investigation status</p>
        </div>
        <div>
          <ShieldQuestion size={22} />
          <span>{Math.round(risk.score || 0)}</span>
          <p>OSINT risk score</p>
        </div>
        <div>
          <Globe2 size={22} />
          <span>{domains.length}</span>
          <p>Domains checked</p>
        </div>
      </div>

      <div className="manual-osint-panel">
        <div className="manual-osint-head">
          <div>
            <p className="eyebrow">Manual OSINT</p>
            <h3>Scan public intelligence</h3>
          </div>
          <button
            className="primary-button compact"
            type="button"
            disabled={manualLoading || !manualText.trim()}
            onClick={() => onManualScan(manualText)}
          >
            {manualLoading ? <Loader2 className="spin" size={17} /> : <SearchCheck size={17} />}
            {manualLoading ? 'Scanning' : 'Scan OSINT'}
          </button>
        </div>
        <textarea
          className="manual-osint-input"
          value={manualText}
          onChange={(event) => setManualText(event.target.value)}
          placeholder="Company, HR email, recruiter name, domain, phone, job role, social links..."
        />
        {manualError && <p className="form-error">{manualError}</p>}
      </div>

      {risk.reasons?.length > 0 && (
        <div className="reason-strip">
          {risk.reasons.map((reason) => (
            <span key={reason}>{reason}</span>
          ))}
        </div>
      )}

      {Object.keys(searchUrls).length > 0 && (
        <div className="search-link-strip">
          {Object.entries(searchUrls).map(([label, url]) => (
            <a key={label} href={url} target="_blank" rel="noreferrer">
              <ExternalLink size={14} />
              {label.replaceAll('_', ' ')}
            </a>
          ))}
        </div>
      )}

      <div className="evidence-grid">
        {evidence.length === 0 ? (
          <p className="empty-state">Public intelligence appears here after the fraud score crosses the OSINT threshold.</p>
        ) : (
          evidence.slice(0, 24).map((item, index) => <EvidenceCard key={`${item.url}-${index}`} item={item} />)
        )}
      </div>

      {sourceStatus.length > 0 && (
        <div className="source-status">
          {sourceStatus.map((source, index) => (
            <span key={`${source.source}-${index}`} className={source.ok ? 'ok' : 'warn'}>
              {String(source.source || 'source').replaceAll('_', ' ')}
            </span>
          ))}
        </div>
      )}

      {domains.length > 0 && (
        <div className="domain-table-wrap">
          <table>
            <thead>
              <tr>
                <th>Domain</th>
                <th>Age</th>
                <th>Registrar</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {domains.map((domain) => (
                <tr key={domain.domain}>
                  <td>{domain.domain}</td>
                  <td>{domain.age_days == null ? 'Unknown' : `${domain.age_days} days`}</td>
                  <td>{domain.registrar || 'Unknown'}</td>
                  <td>{domain.ok ? (domain.suspicious_tld ? 'Watch' : 'Resolved') : 'Unavailable'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

function EvidenceCard({ item }) {
  return (
    <article className="evidence-card">
      <p className="source">{item.source || 'Public source'}</p>
      <h3>{item.title || 'Untitled result'}</h3>
      <p>{item.snippet || 'No summary returned by source.'}</p>
      {item.url && (
        <a href={item.url} target="_blank" rel="noreferrer">
          <ExternalLink size={15} />
          Open source
        </a>
      )}
    </article>
  );
}

export default OsintSection;
