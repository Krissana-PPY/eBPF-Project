'use client';
import { useEffect, useState } from 'react';
import Link from 'next/link';
import { Trash2, ChevronRight, Upload, Clock, FlaskConical } from 'lucide-react';
import { api } from '@/lib/api';
import type { DatasetSummary } from '@/types';

export default function DashboardPage() {
  const [datasets, setDatasets] = useState<DatasetSummary[]>([]);
  const [loading,  setLoading]  = useState(true);
  const [error,    setError]    = useState('');

  const load = async () => {
    try {
      setLoading(true);
      setDatasets(await api.listDatasets());
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed to load');
    } finally {
      setLoading(false);
    }
  };

  const handleDelete = async (id: number, name: string) => {
    if (!confirm(`ลบ dataset "${name}"? ไม่สามารถกู้คืนได้`)) return;
    await api.deleteDataset(id);
    load();
  };

  useEffect(() => { load(); }, []);

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="font-mono text-lg font-semibold text-textdim">Datasets</h1>
          <p className="text-muted text-xs mt-0.5">ชุดข้อมูลผลการทดสอบ QoS ทั้งหมด</p>
        </div>
        <Link href="/upload"
          className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-accent/10 border border-accent/30 text-accent font-mono text-xs hover:bg-accent/20 transition-colors">
          <Upload size={13} />
          อัพโหลดชุดใหม่
        </Link>
      </div>

      {loading && (
        <div className="text-muted text-sm font-mono py-16 text-center">กำลังโหลด...</div>
      )}
      {error && (
        <div className="text-red-400 text-sm font-mono bg-red-400/10 border border-red-400/20 rounded p-4">{error}</div>
      )}

      {!loading && !error && datasets.length === 0 && (
        <div className="text-center py-20 border border-dashed border-border rounded">
          <FlaskConical size={32} className="mx-auto text-muted mb-3" />
          <p className="font-mono text-sm text-muted">ยังไม่มี dataset</p>
          <Link href="/upload" className="text-accent font-mono text-xs hover:underline mt-1 inline-block">
            อัพโหลดผลการทดสอบแรก →
          </Link>
        </div>
      )}

      <div className="flex flex-col gap-3">
        {datasets.map(ds => (
          <div key={ds.id} className="card p-4 flex items-center gap-4 hover:border-border/80 transition-colors group">
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 mb-1">
                <span className="font-mono text-sm font-semibold text-textdim">{ds.name}</span>
                <span className="tag tag-ebpf">{ds.experiment_count} files</span>
              </div>
              {ds.description && (
                <p className="text-muted text-xs truncate">{ds.description}</p>
              )}
              <div className="flex items-center gap-1 mt-1.5 text-muted text-xs font-mono">
                <Clock size={10} />
                {new Date(ds.created_at).toLocaleString('th-TH')}
              </div>
            </div>
            <div className="flex items-center gap-2 opacity-0 group-hover:opacity-100 transition-opacity">
              <button
                onClick={() => handleDelete(ds.id, ds.name)}
                className="p-1.5 rounded hover:bg-red-400/10 text-muted hover:text-red-400 transition-colors">
                <Trash2 size={14} />
              </button>
            </div>
            <Link href={`/dataset/${ds.id}`}
              className="flex items-center gap-1 px-3 py-1.5 rounded bg-surface2 border border-border font-mono text-xs text-muted hover:text-accent hover:border-accent/30 transition-colors">
              วิเคราะห์
              <ChevronRight size={12} />
            </Link>
          </div>
        ))}
      </div>
    </div>
  );
}
