import { BarChart3, CalendarDays, PieChart as PieIcon, TrendingUp } from 'lucide-react';
import { BarChart, LineChart, PieChart } from './Charts.jsx';

function AnalyticsSection({ analytics, stats }) {
  const daily = toSeries(analytics.daily || {});
  const monthly = toSeries(analytics.monthly || {});
  const yearly = toSeries(analytics.yearly || {});
  const fraud = stats.fraud_detections || 0;
  const safe = stats.safe_detections || 0;

  return (
    <section className="workspace-section" id="analytics">
      <div className="section-heading">
        <p className="eyebrow">Analytics</p>
        <h2>Platform Statistics</h2>
      </div>

      <div className="analytics-counters">
        <Metric icon={<CalendarDays size={20} />} label="Daily visitors" value={lastValue(daily, 'visitors')} />
        <Metric icon={<TrendingUp size={20} />} label="Monthly visitors" value={lastValue(monthly, 'visitors')} />
        <Metric icon={<BarChart3 size={20} />} label="Yearly detections" value={lastValue(yearly, 'detections')} />
        <Metric icon={<PieIcon size={20} />} label="Safe detections" value={safe} />
      </div>

      <div className="chart-grid">
        <div className="chart-panel">
          <h3>Daily visitor and detection trend</h3>
          <LineChart data={daily} keys={['visitors', 'detections']} />
        </div>
        <div className="chart-panel">
          <h3>Monthly detections</h3>
          <BarChart data={monthly} valueKey="detections" />
        </div>
        <div className="chart-panel">
          <h3>Fraud vs safe</h3>
          <PieChart data={[{ label: 'Fraud', value: fraud }, { label: 'Safe', value: safe }]} />
        </div>
      </div>

      <div className="recent-table-wrap">
        <table>
          <thead>
            <tr>
              <th>Time</th>
              <th>Score</th>
              <th>Risk</th>
              <th>Class</th>
            </tr>
          </thead>
          <tbody>
            {(stats.recent_detections || []).slice(0, 8).map((item) => (
              <tr key={item.timestamp}>
                <td>{new Date(item.timestamp).toLocaleString()}</td>
                <td>{Math.round(item.fraud_score)}</td>
                <td>{item.risk_level}</td>
                <td>{item.classification}</td>
              </tr>
            ))}
            {(stats.recent_detections || []).length === 0 && (
              <tr>
                <td colSpan="4">No detections recorded yet.</td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </section>
  );
}

function Metric({ icon, label, value }) {
  return (
    <div>
      {icon}
      <span>{value}</span>
      <p>{label}</p>
    </div>
  );
}

function toSeries(bucket) {
  return Object.entries(bucket)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([label, values]) => ({ label, ...values }));
}

function lastValue(series, key) {
  if (!series.length) return 0;
  return series[series.length - 1][key] || 0;
}

export default AnalyticsSection;

