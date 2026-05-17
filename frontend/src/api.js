const BACKEND_URL = (import.meta.env.VITE_BACKEND_URL).replace(/\/$/, '');

async function parseResponse(response) {
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(data.detail || data.message || `Request failed with ${response.status}`);
  }
  return data;
}

export async function analyzeText(text, sourceType = 'text') {
  const response = await fetch(`${BACKEND_URL}/analyze`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ text, source_type: sourceType }),
  });
  return parseResponse(response);
}

export async function uploadFile(file, sourceType = 'upload') {
  const body = new FormData();
  body.append('file', file);
  body.append('source_type', sourceType);
  const response = await fetch(`${BACKEND_URL}/upload`, {
    method: 'POST',
    body,
  });
  return parseResponse(response);
}

export async function runManualOsint(text, fraudScore = 20) {
  const response = await fetch(`${BACKEND_URL}/osint`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ text, fraud_score: fraudScore }),
  });
  return parseResponse(response);
}

export async function getStats() {
  const response = await fetch(`${BACKEND_URL}/stats`);
  return parseResponse(response);
}

export async function getAnalytics() {
  const response = await fetch(`${BACKEND_URL}/analytics`);
  return parseResponse(response);
}

export { BACKEND_URL };
