/**
 * useStats.js
 *
 * Strategy:
 *  1. On mount, read cached counts from localStorage → display instantly (no spinner).
 *  2. Immediately increment visitCount in localStorage (optimistic, before backend replies).
 *  3. Fire a background request to the analytics endpoint.
 *     • If backend responds  → take max(backend, local) so counts never go backwards.
 *     • If backend is asleep → local values are already shown; we just try again silently.
 *  4. Return { visitCount, fraudCount, loading, synced } to the component.
 *     `synced` becomes true once the backend has confirmed/updated the numbers.
 *
 * Drop this file into: frontend/src/hooks/useStats.js
 */

import { useState, useEffect, useRef, useCallback } from "react";

// ─── constants ────────────────────────────────────────────────────────────────
const STORAGE_KEY   = "fraudlens_stats";
const SYNC_INTERVAL = 60_000;          // re-sync every 60 s once backend is up
const RETRY_DELAY   = 15_000;          // retry backend after 15 s if it was sleeping
const ANALYTICS_URL = import.meta.env.VITE_ANALYTICS_URL
  ?? `${import.meta.env.VITE_BACKEND_URL ?? ""}/analytics`;

// ─── localStorage helpers ─────────────────────────────────────────────────────
function readCache() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return null;
    return JSON.parse(raw);               // { visitCount, fraudCount, ts }
  } catch {
    return null;
  }
}

function writeCache(visitCount, fraudCount) {
  try {
    localStorage.setItem(
      STORAGE_KEY,
      JSON.stringify({ visitCount, fraudCount, ts: Date.now() })
    );
  } catch {
    /* storage full – silently ignore */
  }
}

// ─── hook ─────────────────────────────────────────────────────────────────────
export function useStats() {
  // Seed from cache so we can render instantly
  const cache = readCache();

  const [visitCount, setVisitCount] = useState(cache?.visitCount ?? 0);
  const [fraudCount, setFraudCount] = useState(cache?.fraudCount ?? 0);
  const [loading,    setLoading]    = useState(!cache);   // only show "loading" on first ever visit
  const [synced,     setSynced]     = useState(false);    // true once backend confirmed values

  const visitRef = useRef(visitCount);  // keep ref in sync so closures see latest value
  const fraudRef = useRef(fraudCount);

  // helper to update both state + ref + cache atomically
  const commit = useCallback((v, f) => {
    visitRef.current = v;
    fraudRef.current = f;
    setVisitCount(v);
    setFraudCount(f);
    writeCache(v, f);
  }, []);

  // ── Step 1: Optimistic visitor increment (instant, before backend replies) ──
  useEffect(() => {
    const incremented = (cache?.visitCount ?? 0) + 1;
    commit(incremented, cache?.fraudCount ?? 0);
    setLoading(false);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);   // run once on mount

  // ── Step 2 & 3: Background sync with backend ─────────────────────────────
  useEffect(() => {
    let retryTimer   = null;
    let intervalTimer = null;
    let unmounted    = false;

    async function syncWithBackend() {
      try {
        const controller = new AbortController();
        const timeoutId  = setTimeout(() => controller.abort(), 10_000);

        const res = await fetch(ANALYTICS_URL, { signal: controller.signal });
        clearTimeout(timeoutId);

        if (!res.ok) throw new Error(`HTTP ${res.status}`);

        const data = await res.json();
        if (unmounted) return;

        // Map your backend field names here ↓
        const backendVisits = Number(
          data.total_visitors ?? data.totalVisitors ?? data.visitor_count ?? 0
        );
        const backendFrauds = Number(
          data.total_detections ?? data.totalDetections ?? data.fraud_count ?? 0
        );

        // Take the maximum so numbers never go backwards
        const finalVisits = Math.max(visitRef.current, backendVisits);
        const finalFrauds = Math.max(fraudRef.current, backendFrauds);

        commit(finalVisits, finalFrauds);
        setSynced(true);

        // Schedule periodic re-sync now that backend is awake
        if (!intervalTimer) {
          intervalTimer = setInterval(syncWithBackend, SYNC_INTERVAL);
        }
      } catch (err) {
        if (unmounted) return;
        // Backend still sleeping – retry quietly after RETRY_DELAY
        retryTimer = setTimeout(syncWithBackend, RETRY_DELAY);
      }
    }

    syncWithBackend();

    return () => {
      unmounted = true;
      clearTimeout(retryTimer);
      clearInterval(intervalTimer);
    };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [commit]);

  return { visitCount, fraudCount, loading, synced };
}