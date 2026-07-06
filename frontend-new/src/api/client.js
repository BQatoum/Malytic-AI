// In dev, Vite proxies /api → localhost:8000. In production, set VITE_API_BASE.
const BASE = import.meta.env.VITE_API_BASE ?? '/api';

async function request(path, options = {}) {
  const res = await fetch(`${BASE}${path}`, options);
  if (!res.ok) {
    const text = await res.text().catch(() => '');
    let message = `${res.status} ${res.statusText}`;
    try {
      const json = JSON.parse(text);
      if (typeof json.detail === 'string') {
        message = json.detail;
      } else if (json.detail) {
        // FastAPI validation errors come as arrays of objects
        message = Array.isArray(json.detail)
          ? json.detail.map(e => e.msg || JSON.stringify(e)).join('; ')
          : JSON.stringify(json.detail);
      }
    } catch { /* response wasn't JSON — keep status-based message */ }
    throw Object.assign(new Error(message), { status: res.status, body: text });
  }
  return res;
}

export async function listCases() {
  const res = await request('/cases');
  return res.json();
}

export async function getCase(caseId) {
  const res = await request(`/cases/${caseId}`);
  return res.json();
}

export async function submitSample(file, password = 'infected', options = {}) {
  const fd = new FormData();
  fd.append('file', file);
  fd.append('password', password);
  fd.append('report_format', 'markdown');
  if (options.iocFile) {
    fd.append('ioc_file', options.iocFile);
  }
  if (options.staticFindingsFile) {
    fd.append('static_findings_file', options.staticFindingsFile);
  }
  if (options.dynamicFindingsFile) {
    fd.append('dynamic_findings_file', options.dynamicFindingsFile);
  }
  if (options.pauseForOsint) {
    fd.append('pause_for_osint', 'true');
  }
  const res = await request('/analyze', { method: 'POST', body: fd });
  return res.json();
}

export function reportPdfUrl(caseId) {
  return `${BASE}/cases/${caseId}/report.pdf`;
}

export function screenshotUrl(caseId, idx) {
  return `${BASE}/cases/${caseId}/screenshots/${idx}`;
}

export function intermediateFindingsUrl(caseId) {
  return `${BASE}/cases/${caseId}/intermediate-findings`;
}

export function iocExportUrl(caseId) {
  return `${BASE}/cases/${caseId}/ioc-export`;
}

export async function resumeWithOsint(caseId, osintFile) {
  const fd = new FormData();
  fd.append('osint_file', osintFile);
  const res = await request(`/cases/${caseId}/resume-with-osint`, {
    method: 'POST',
    body: fd,
  });
  return res.json();
}
