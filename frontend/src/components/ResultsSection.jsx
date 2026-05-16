import { AlertTriangle, CheckCircle2, Gauge, ShieldAlert } from 'lucide-react';

function ResultsSection({ result, loading }) {
  const fraudScore = result?.fraud_score ?? 0;
  const safeScore = result?.legitimacy_score ?? 0;

  return (
    <section className="workspace-section" id="results">
      <div className="section-heading">
        <p className="eyebrow">Detection Results</p>
        <h2>Risk Decision</h2>
      </div>

      <div className="result-grid">
        <div className="score-panel">
          <div className="gauge" style={{ '--score': `${fraudScore * 3.6}deg` }}>
            <div>
              <span>{Math.round(fraudScore)}</span>
              <small>Fraud score</small>
            </div>
          </div>
          <div className="risk-lines">
            <p>
              <Gauge size={17} />
              Risk level: <strong>{result?.risk_level || (loading ? 'running' : 'pending')}</strong>
            </p>
            <p>
              <CheckCircle2 size={17} />
              Legitimacy score: <strong>{Math.round(safeScore)}</strong>
            </p>
            <p>
              <ShieldAlert size={17} />
              Confidence: <strong>{Math.round(result?.confidence || 0)}</strong>
            </p>
          </div>
        </div>

        <div className="explanation-panel">
          <h3>AI reasoning summary</h3>
          <p>{result?.explanation || 'Submit content to generate a fraud score, explanation, highlighted terms, and OSINT trigger decision.'}</p>
          <div className="metric-strip">
            <span>ML {Math.round(result?.ml_score || 0)}</span>
            <span>Rules {Math.round(result?.rule_score || 0)}</span>
            <span>{Math.round(result?.processing_time_ms || 0)} ms</span>
          </div>
        </div>
      </div>

      <div className="indicator-grid">
        <IndicatorList
          title="Suspicious terms"
          icon={<AlertTriangle size={18} />}
          items={result?.suspicious_terms || []}
          tone="danger"
        />
        <IndicatorList
          title="Legitimate indicators"
          icon={<CheckCircle2 size={18} />}
          items={result?.legitimate_indicators || []}
          tone="safe"
        />
      </div>
    </section>
  );
}

function IndicatorList({ title, icon, items, tone }) {
  return (
    <div className="indicator-panel">
      <h3>
        {icon}
        {title}
      </h3>
      {items.length === 0 ? (
        <p className="muted">No entries detected yet.</p>
      ) : (
        <ul className="indicator-list">
          {items.slice(0, 8).map((item, index) => (
            <li key={`${item.term}-${index}`} className={tone}>
              <strong>{item.term}</strong>
              <span>{item.reason}</span>
              {item.snippet && <em>{item.snippet}</em>}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

export default ResultsSection;

