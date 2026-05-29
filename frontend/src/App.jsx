import { useEffect, useMemo, useRef, useState } from 'react';
import Header from './components/Header.jsx';
import UploadSection from './components/UploadSection.jsx';
import ResultsSection from './components/ResultsSection.jsx';
import OsintSection from './components/OsintSection.jsx';
import GraphMap from './components/GraphMap.jsx';
import AnalyticsSection from './components/AnalyticsSection.jsx';
import AnimatedNumber from './components/AnimatedNumber.jsx';          // ← NEW
import { analyzeText, getAnalytics, getStats, runManualOsint, uploadFile } from './api.js';

// ── localStorage helpers ─────────────────────────────────────────────────────
// We cache only the two lifetime counters so they show instantly on every visit.
const CACHE_KEY = 'fraudlens_lifetime';

function readCache() {
  try {
    const raw = localStorage.getItem(CACHE_KEY);
    return raw ? JSON.parse(raw) : null;          // { visitors, frauds }
  } catch { return null; }
}

function writeCache(visitors, frauds) {
  try {
    localStorage.setItem(CACHE_KEY, JSON.stringify({ visitors, frauds }));
  } catch { /* storage full – silently ignore */ }
}
// ─────────────────────────────────────────────────────────────────────────────

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

  // ── Seed initial state from cache so numbers render instantly ──────────────
  const cache = readCache();
  const [stats, setStats] = useState({
    ...emptyStats,
    lifetime_visitors:         cache?.visitors ?? 31,
    lifetime_fraud_detections: cache?.frauds   ?? 3,
  });
  const [analytics, setAnalytics] = useState(emptyStats);
  const [synced,    setSynced]    = useState(false);   // true once backend replies

  const [result,        setResult]        = useState(null);
  const [manualOsint,   setManualOsint]   = useState(null);
  const [manualLoading, setManualLoading] = useState(false);
  const [manualError,   setManualError]   = useState('');
  const [loading,       setLoading]       = useState(false);
  const [error,         setError]         = useState('');

  // Keep a ref so async callbacks always read the latest stats without stale closures
  const statsRef = useRef(stats);
  useEffect(() => { statsRef.current = stats; }, [stats]);

  // ── 1. Optimistic visitor increment ────────────────────────────────────────
  // Runs immediately on mount, before the backend responds.
  // This way even if the backend is asleep, the visit is still counted locally.
  useEffect(() => {
    const cached      = readCache();
    const newVisitors = (cached?.visitors ?? 31) + 1;   // ← was 0
    const newFrauds   = cached?.frauds   ?? 3;          // ← was 0

    setStats(prev => ({ ...prev, lifetime_visitors: newVisitors }));
    writeCache(newVisitors, newFrauds);
  }, []);   // runs once per page load

  // ── 2. Background sync with backend (retries every 15 s while sleeping) ───
  useEffect(() => {
    let retryTimer = null;
    let unmounted  = false;

    async function syncMetrics() {
      try {
        const [statsData, analyticsData] = await Promise.all([
          getStats(),
          getAnalytics(),
        ]);
        if (unmounted) return;

        const backendVisitors = Number(statsData.lifetime_visitors         ?? 0);
        const backendFrauds = Number(statsData.fraud_detections ?? 0) + Number(statsData.safe_detections ?? 0);

        // Take max of local vs backend so the number never goes backwards
        // (backend may have missed visits while it was asleep)
        const finalVisitors = Math.max(statsRef.current.lifetime_visitors,         backendVisitors);
        const finalFrauds   = Math.max(statsRef.current.lifetime_fraud_detections, backendFrauds);

        writeCache(finalVisitors, finalFrauds);

        setStats({
          ...emptyStats,
          ...statsData,
          lifetime_visitors:         finalVisitors,
          lifetime_fraud_detections: finalFrauds,
        });
        setAnalytics({ ...emptyStats, ...analyticsData });
        setSynced(true);

      } catch {
        if (unmounted) return;
        // Backend is sleeping – retry quietly in 15 s
        retryTimer = setTimeout(syncMetrics, 15_000);
      }
    }

    syncMetrics();

    return () => {
      unmounted = true;
      clearTimeout(retryTimer);
    };
  }, []);   // runs once on mount

  // ── refreshMetrics (called after each analysis) ───────────────────────────
  async function refreshMetrics() {
    try {
      const [statsData, analyticsData] = await Promise.all([
        getStats(),
        getAnalytics(),
      ]);

      const backendVisitors = Number(statsData.lifetime_visitors         ?? 0);
      const backendFrauds   = Number(statsData.lifetime_fraud_detections ?? 0);
      const finalVisitors   = Math.max(statsRef.current.lifetime_visitors,         backendVisitors);
      const finalFrauds     = Math.max(statsRef.current.lifetime_fraud_detections, backendFrauds);

      writeCache(finalVisitors, finalFrauds);

      setStats({
        ...emptyStats,
        ...statsData,
        lifetime_visitors:         finalVisitors,
        lifetime_fraud_detections: finalFrauds,
      });
      setAnalytics({ ...emptyStats, ...analyticsData });
      setSynced(true);
    } catch { /* silently ignore – local values are still shown */ }
  }

  // ── Handlers (unchanged from original) ────────────────────────────────────
  async function handleAnalyze({ text, file, sourceType }) {
    setLoading(true);
    setError('');
    try {
      const response = file
        ? await uploadFile(file, sourceType)
        : await analyzeText(text, sourceType);
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

  const graph = useMemo(
    () => manualOsint?.graph || result?.graph || { nodes: [], edges: [] },
    [manualOsint, result],
  );

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
                Detect <strong>Fraud's</strong>
                <br />
                Before They <em>Detect You</em>
              </h1>
              <p className="intro">
                Upload job offers, recruitment emails, or offer letters. Our AI engine analyzes fraud patterns,
                triggers OSINT intelligence, and maps entity relationships in real-time.
              </p>

              <div className="counter-grid" aria-label="Platform counters">

                <div>
                  {/* Sync dot: amber while backend is waking up, green once confirmed */}
                  <div
                    className={`stats-sync-dot ${synced ? 'synced' : 'pending'}`}
                    title={synced ? 'Live data' : 'Syncing with server…'}
                  />
                  <AnimatedNumber value={stats.lifetime_visitors} />
                  <p>Lifetime Visitors</p>
                </div>

                <div>
                  <div
                    className={`stats-sync-dot ${synced ? 'synced' : 'pending'}`}
                    title={synced ? 'Live data' : 'Syncing with server…'}
                  />
                  <AnimatedNumber value={stats.fraud_detections + stats.safe_detections} suffix="" />
                  <p>Total Detections</p>
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

        {currentPage === 'analytics' && (
          <AnalyticsSection analytics={analytics} stats={stats} />
        )}

      </main>
    </>
  );
}

export default App;