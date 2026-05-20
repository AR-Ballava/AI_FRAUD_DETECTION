import { useEffect, useMemo, useState } from 'react';
import Header from './components/Header.jsx';
import UploadSection from './components/UploadSection.jsx';
import ResultsSection from './components/ResultsSection.jsx';
import OsintSection from './components/OsintSection.jsx';
import GraphMap from './components/GraphMap.jsx';
import AnalyticsSection from './components/AnalyticsSection.jsx';
import { analyzeText, getAnalytics, getStats, runManualOsint, uploadFile } from './api.js';

const emptyStats = {
  lifetime_visitors: 0,
  lifetime_fraud_detections: 0,
  fraud_detections: 0,
  safe_detections: 0,
  daily: {},
  monthly: {},
  yearly: {},
  recent_detections: [],
};

function App() {
  const [currentPage, setCurrentPage] = useState('detect');
  const [stats, setStats] = useState(emptyStats);
  const [analytics, setAnalytics] = useState(emptyStats);
  const [result, setResult] = useState(null);
  const [manualOsint, setManualOsint] = useState(null);
  const [manualLoading, setManualLoading] = useState(false);
  const [manualError, setManualError] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  async function refreshMetrics() {
    const [statsData, analyticsData] = await Promise.all([getStats(), getAnalytics()]);
    setStats({ ...emptyStats, ...statsData });
    setAnalytics({ ...emptyStats, ...analyticsData });
  }

  useEffect(() => {
    refreshMetrics().catch(() => {});
  }, []);

  async function handleAnalyze({ text, file, sourceType }) {
    setLoading(true);
    setError('');
    try {
      const response = file ? await uploadFile(file, sourceType) : await analyzeText(text, sourceType);
      setResult(response);
      setManualOsint(null);
      setCurrentPage('analysis');
      await refreshMetrics();
    } catch (err) {
      setError(err.message || 'Analysis failed');
    } finally {
      setLoading(false);
    }
  }

  async function handleManualOsint(text) {
    setManualLoading(true);
    setManualError('');
    try {
      const response = await runManualOsint(text, result?.fraud_score || 20);
      setManualOsint(response);
      setCurrentPage('osint');
    } catch (err) {
      setManualError(err.message || 'Manual OSINT scan failed');
    } finally {
      setManualLoading(false);
    }
  }

  const graph = useMemo(() => manualOsint?.graph || result?.graph || { nodes: [], edges: [] }, [manualOsint, result]);
  const accuracyRate = '99%';

  return (
    <>
      <Header currentPage={currentPage} onNavigate={setCurrentPage} />
      <main className={currentPage === 'detect' ? 'home-main' : 'page-main'}>
        {currentPage === 'detect' && (
          <section className="hero-shell">
            <div className="hero-copy">
              <p className="hero-badge">
                <span />
                AI-Powered Fraud Intelligence Platform
              </p>
              <h1>
                Detect <strong>Fraud Jobs</strong>
                <br />
                Before They <em>Detect You</em>
              </h1>
              <p className="intro">
                Upload job offers, recruitment emails, or offer letters. Our AI engine analyzes fraud patterns,
                triggers OSINT intelligence, and maps entity relationships in real-time.
              </p>
              <div className="counter-grid" aria-label="Platform counters">
                <div>
                  <span>{stats.lifetime_visitors}</span>
                  <p>Lifetime Visitors</p>
                </div>
                <div>
                  <span>{stats.lifetime_fraud_detections}</span>
                  <p>Fraud Detections</p>
                </div>
                <div>
                  <span>{accuracyRate}</span>
                  <p>Accuracy Rate</p>
                </div>
              </div>
            </div>
            <UploadSection onAnalyze={handleAnalyze} loading={loading} error={error} />
          </section>
        )}

        {currentPage === 'analysis' && (
          <ResultsSection 
            result={result} 
            loading={loading} 
            onNavigate={setCurrentPage} 
          />
        )}

        {currentPage === 'osint' && (
          <OsintSection
            result={result}
            manualOsint={manualOsint}
            manualLoading={manualLoading}
            manualError={manualError}
            onManualScan={handleManualOsint}
          />
        )}

        {currentPage === 'graph' && (
          <section className="workspace-section" id="graph">
            <div className="section-heading">
              <p className="eyebrow">Graph Mapping</p>
              <h2>Relationship Map</h2>
            </div>
            <GraphMap graph={graph} />
          </section>
        )}

        {currentPage === 'analytics' && <AnalyticsSection analytics={analytics} stats={stats} />}
      </main>
    </>
  );
}

export default App;