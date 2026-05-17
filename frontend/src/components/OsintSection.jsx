import {
  AlertTriangle,
  ExternalLink,
  Globe2,
  Loader2,
  Radar,
  SearchCheck,
  ShieldAlert,
  ShieldCheck,
  ShieldQuestion,
} from 'lucide-react';

import { useMemo, useState } from 'react';

function OsintSection({
  result,
  manualOsint,
  manualLoading,
  manualError,
  onManualScan,
}) {
  const [manualText, setManualText] = useState('');

  const osint = manualOsint || result?.osint;

  const risk = osint?.risk || {
    score: 0,
    level: 'pending',
    reasons: [],
  };

  const evidence = osint?.evidence || [];
  const domains = osint?.domain_intelligence || [];
  const searchUrls = osint?.search_urls || {};
  const sourceStatus = osint?.source_status || [];

  // IMPORTANT FEATURE
  const suspiciousEntities = osint?.suspicious_entities || [];

  const investigationMode = manualOsint
    ? 'Manual'
    : result?.osint_triggered
    ? 'Triggered'
    : 'Waiting';

  const riskConfig = useMemo(() => {
    const level = String(risk.level || '').toLowerCase();

    if (level === 'critical') {
      return {
        label: 'Critical Risk',
        className: 'critical',
        icon: <ShieldAlert size={18} />,
      };
    }

    if (level === 'high') {
      return {
        label: 'High Risk',
        className: 'high',
        icon: <AlertTriangle size={18} />,
      };
    }

    if (level === 'medium') {
      return {
        label: 'Medium Risk',
        className: 'medium',
        icon: <ShieldQuestion size={18} />,
      };
    }

    return {
      label: 'Low Risk',
      className: 'low',
      icon: <ShieldCheck size={18} />,
    };
  }, [risk.level]);

  return (
    <section className="workspace-section" id="osint">
      <div className="section-heading">
        <p className="eyebrow">OSINT Intelligence</p>
        <h2>Advanced Public Intelligence Investigation</h2>
      </div>

      {/* SUMMARY */}
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

        <div>
          <AlertTriangle size={22} />
          <span>{suspiciousEntities.length}</span>
          <p>Suspicious entities</p>
        </div>
      </div>

      {/* RISK BANNER */}
      <div className={`risk-banner ${riskConfig.className}`}>
        <div className="risk-banner-left">
          {riskConfig.icon}

          <div>
            <h3>{riskConfig.label}</h3>

            <p>
              Overall OSINT Risk Score:{' '}
              <strong>{Math.round(risk.score || 0)}</strong>
            </p>
          </div>
        </div>
      </div>

      {/* MANUAL OSINT */}
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
            {manualLoading ? (
              <Loader2 className="spin" size={17} />
            ) : (
              <SearchCheck size={17} />
            )}

            {manualLoading ? 'Scanning' : 'Scan OSINT'}
          </button>
        </div>

        <textarea
          className="manual-osint-input"
          value={manualText}
          onChange={(event) => setManualText(event.target.value)}
          placeholder="Company Name, Company Domain, HR email, recruiter name, phone, job role..."
        />

        {manualError && <p className="form-error">{manualError}</p>}
      </div>

      {/* RISK REASONS */}
      {risk.reasons?.length > 0 && (
        <div className="reason-strip">
          {risk.reasons.map((reason) => (
            <span key={reason}>{reason}</span>
          ))}
        </div>
      )}

      {/* SUSPICIOUS ENTITIES */}
      <div className="suspicious-entities-section">
        <div className="section-sub-heading">
          <h3>Top Suspicious Entities</h3>

          <p>
            Ranked entities based on fraud keyword proximity,
            external scam reports, contextual intelligence,
            and OSINT evidence.
          </p>
        </div>

        {suspiciousEntities.length === 0 ? (
          <div className="empty-state-box">
            <ShieldCheck size={22} />
            <p>No suspicious entities detected.</p>
          </div>
        ) : (
          <div className="suspicious-grid">
            {suspiciousEntities.map((entity, index) => (
              <SuspiciousEntityCard
                key={`${entity.entity}-${index}`}
                entity={entity}
                rank={index + 1}
              />
            ))}
          </div>
        )}
      </div>

      {/* SEARCH LINKS */}
      {Object.keys(searchUrls).length > 0 && (
        <div className="search-link-strip">
          {Object.entries(searchUrls).map(([label, url]) => (
            <a
              key={label}
              href={url}
              target="_blank"
              rel="noreferrer"
            >
              <ExternalLink size={14} />
              {label.replaceAll('_', ' ')}
            </a>
          ))}
        </div>
      )}

      {/* PUBLIC EVIDENCE */}
      <div className="section-sub-heading">
        <h3>Public Intelligence Evidence</h3>

        <p>
          External evidence collected from public sources,
          complaint platforms, forums, social discussions,
          and OSINT intelligence providers.
        </p>
      </div>

      <div className="evidence-grid">
        {evidence.length === 0 ? (
          <p className="empty-state">
            Public intelligence appears here after OSINT investigation.
          </p>
        ) : (
          evidence
            .slice(0, 24)
            .map((item, index) => (
              <EvidenceCard
                key={`${item.url}-${index}`}
                item={item}
              />
            ))
        )}
      </div>

      {/* SOURCE STATUS */}
      {sourceStatus.length > 0 && (
        <div className="source-status">
          {sourceStatus.map((source, index) => (
            <span
              key={`${source.source}-${index}`}
              className={source.ok ? 'ok' : 'warn'}
            >
              {String(source.source || 'source').replaceAll('_', ' ')}
            </span>
          ))}
        </div>
      )}

      {/* DOMAIN TABLE */}
      {domains.length > 0 && (
        <div className="domain-table-wrap">
          <div className="section-sub-heading">
            <h3>Domain Intelligence</h3>
          </div>

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

                  <td>
                    {domain.age_days == null
                      ? 'Unknown'
                      : `${domain.age_days} days`}
                  </td>

                  <td>{domain.registrar || 'Unknown'}</td>

                  <td>
                    {domain.ok
                      ? domain.suspicious_tld
                        ? 'Watch'
                        : 'Resolved'
                      : 'Unavailable'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

function SuspiciousEntityCard({ entity, rank }) {
  const score = Number(entity.score || 0);

  let severity = 'low';
  let isCriticalHighlight = false;

  if (score >= 85) {
    severity = 'critical';
    isCriticalHighlight = true;
  } else if (score >= 70) {
    severity = 'high';
    isCriticalHighlight = true;
  } else if (score >= 40) {
    severity = 'medium';
  }

  return (
    <article
      className={`suspicious-card ${severity} ${
        isCriticalHighlight ? 'critical-highlight' : ''
      }`}
    >
      <div className="suspicious-card-top">
        <div className="entity-rank">#{rank}</div>

        <div className={`entity-score ${severity}`}>
          {Math.round(score)}
        </div>
      </div>

      {score >= 70 && (
        <div className="danger-badge">
          HIGH RISK
        </div>
      )}

      <div className="entity-type-row">
        <span className="entity-type">{entity.type}</span>

        {entity.external_evidence_count > 0 && (
          <span className="external-count">
            {entity.external_evidence_count} external reports
          </span>
        )}
      </div>

      <h3 className="entity-value">{entity.entity}</h3>

      {entity.evidence_summary && (
        <p className="entity-summary">
          {entity.evidence_summary}
        </p>
      )}

      {entity.matched_keywords?.length > 0 && (
        <div className="keyword-list">
          {entity.matched_keywords.map((keyword) => (
            <span key={keyword}>{keyword}</span>
          ))}
        </div>
      )}

      {entity.context && (
        <div className="entity-context">
          <h4>Evidence Context</h4>

          <p>{entity.context}</p>
        </div>
      )}
    </article>
  );
}

function EvidenceCard({ item }) {
  return (
    <article className="evidence-card">
      <p className="source">
        {item.source || 'Public source'}
      </p>

      <h3>{item.title || 'Untitled result'}</h3>

      <p>
        {item.snippet || 'No summary returned by source.'}
      </p>

      {item.url && (
        <a
          href={item.url}
          target="_blank"
          rel="noreferrer"
        >
          <ExternalLink size={15} />
          Open source
        </a>
      )}
    </article>
  );
}

export default OsintSection;