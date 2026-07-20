import type { Dataset, DatasetSummary, ExperimentSummary, ExperimentDetail, ModeData, QosType } from '@/types';

const BASE = '/api';

async function req<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    headers: { 'Content-Type': 'application/json', ...init?.headers },
    ...init,
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: res.statusText }));
    throw new Error(err.error || `HTTP ${res.status}`);
  }
  return res.json();
}

export const api = {
  listDatasets:   ()           => req<DatasetSummary[]>('/datasets'),
  getDataset:     (id: number) => req<Dataset>(`/datasets/${id}`),
  createDataset:  (body: { name: string; description?: string }) =>
    req<DatasetSummary>('/datasets', { method: 'POST', body: JSON.stringify(body) }),
  deleteDataset:  (id: number) =>
    req<{ success: boolean }>(`/datasets/${id}`, { method: 'DELETE' }),

  uploadFiles: (datasetId: number, files: FileList | File[]) => {
    const form = new FormData();
    const fileArr = Array.from(files);
    fileArr.forEach(f => form.append('files', f));
    // webkitRelativePath (populated when a whole folder is selected) carries
    // the fair_benchmark_trials/trial_N number — filenames alone repeat across
    // trials, so the backend needs the path to tell them apart.
    const paths = fileArr.map(f => (f as File & { webkitRelativePath?: string }).webkitRelativePath || '');
    form.append('paths', JSON.stringify(paths));
    return fetch(`${BASE}/upload/${datasetId}`, { method: 'POST', body: form })
      .then(r => r.json());
  },

  listExperiments: (datasetId: number) =>
    req<ExperimentSummary[]>(`/experiments/dataset/${datasetId}`),

  getExperiment: (id: number) =>
    req<ExperimentDetail>(`/experiments/${id}`),

  getModeData: (datasetId: number, qosType: QosType) =>
    req<ModeData>(`/datasets/${datasetId}/mode/${qosType}`),

  downloadModeReport: async (datasetId: number, qosType: QosType) => {
    const res = await fetch(`${BASE}/datasets/${datasetId}/mode/${qosType}/report`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const blob = await res.blob();
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href     = url;
    a.download = `ebpf-mode-${qosType}-${datasetId}.md`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  },

  downloadExperimentReport: async (id: number, slug: string) => {
    const res = await fetch(`${BASE}/experiments/${id}/report`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const blob = await res.blob();
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href     = url;
    a.download = `ebpf-exp-${slug}.md`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  },
};
