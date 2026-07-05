'use client';
import { useState, useRef, DragEvent } from 'react';
import { useRouter } from 'next/navigation';
import { Upload, CheckCircle, XCircle, FileText, Loader2 } from 'lucide-react';
import { api } from '@/lib/api';
import clsx from 'clsx';

interface FileResult {
  file: string; status: 'ok' | 'error';
  qosType?: string; trafficClass?: string; experimentType?: string;
  error?: string;
}

export default function UploadPage() {
  const router = useRouter();
  const inputRef = useRef<HTMLInputElement>(null);

  const [name,        setName]        = useState('');
  const [description, setDescription] = useState('');
  const [files,       setFiles]       = useState<File[]>([]);
  const [dragging,    setDragging]    = useState(false);
  const [busy,        setBusy]        = useState(false);
  const [results,     setResults]     = useState<FileResult[] | null>(null);
  const [globalError, setGlobalError] = useState('');

  const addFiles = (fl: FileList | null) => {
    if (!fl) return;
    const valid = Array.from(fl).filter(f => /\.(json|txt)$/i.test(f.name));
    setFiles(prev => {
      const names = new Set(prev.map(f => f.name));
      return [...prev, ...valid.filter(f => !names.has(f.name))];
    });
  };

  const onDrop = (e: DragEvent) => {
    e.preventDefault(); setDragging(false);
    addFiles(e.dataTransfer.files);
  };

  const removeFile = (name: string) =>
    setFiles(prev => prev.filter(f => f.name !== name));

  const handleSubmit = async () => {
    if (!name.trim())        return setGlobalError('กรุณาใส่ชื่อ dataset');
    if (!files.length)       return setGlobalError('กรุณาเลือกไฟล์อย่างน้อย 1 ไฟล์');
    setGlobalError(''); setBusy(true); setResults(null);
    try {
      const ds   = await api.createDataset({ name: name.trim(), description: description.trim() || undefined });
      const res  = await api.uploadFiles(ds.id, files);
      setResults(res.results);
      setTimeout(() => router.push(`/dataset/${ds.id}`), 2000);
    } catch (e: unknown) {
      setGlobalError(e instanceof Error ? e.message : 'เกิดข้อผิดพลาด');
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="max-w-2xl mx-auto">
      <h1 className="font-mono text-lg font-semibold text-textdim mb-1">อัพโหลดชุดข้อมูลใหม่</h1>
      <p className="text-muted text-xs font-mono mb-6">รองรับ .json (iperf3, eBPF map) และ .txt (sar CPU, tc stats)</p>

      <div className="flex flex-col gap-4">
        {/* Name */}
        <div>
          <label className="font-mono text-xs text-muted block mb-1">ชื่อ Dataset *</label>
          <input value={name} onChange={e => setName(e.target.value)}
            placeholder="เช่น Test Run June 2026"
            className="w-full bg-surface border border-border rounded px-3 py-2 font-mono text-sm text-textdim focus:outline-none focus:border-accent/50 transition-colors" />
        </div>

        {/* Description */}
        <div>
          <label className="font-mono text-xs text-muted block mb-1">คำอธิบาย (optional)</label>
          <textarea value={description} onChange={e => setDescription(e.target.value)} rows={2}
            placeholder="เงื่อนไขการทดสอบ, bandwidth, หมายเหตุ..."
            className="w-full bg-surface border border-border rounded px-3 py-2 font-mono text-sm text-textdim focus:outline-none focus:border-accent/50 transition-colors resize-none" />
        </div>

        {/* Drop zone */}
        <div
          onDragOver={e => { e.preventDefault(); setDragging(true); }}
          onDragLeave={() => setDragging(false)}
          onDrop={onDrop}
          onClick={() => inputRef.current?.click()}
          className={clsx(
            'border-2 border-dashed rounded-lg p-8 text-center cursor-pointer transition-colors',
            dragging ? 'border-accent/60 bg-accent/5' : 'border-border hover:border-accent/30 hover:bg-surface/50'
          )}>
          <Upload size={28} className={clsx('mx-auto mb-3', dragging ? 'text-accent' : 'text-muted')} />
          <p className="font-mono text-sm text-textdim">ลากไฟล์มาวาง หรือคลิกเพื่อเลือก</p>
          <p className="font-mono text-xs text-muted mt-1">
            รูปแบบ: <code className="text-accent">no_qos_tcp_ef.json</code>,&nbsp;
            <code className="text-htb">htb_tcp_cpu.txt</code>, ...
          </p>
          <input ref={inputRef} type="file" multiple accept=".json,.txt"
            className="hidden" onChange={e => addFiles(e.target.files)} />
        </div>

        {/* File list */}
        {files.length > 0 && (
          <div className="card overflow-hidden">
            <div className="px-3 py-2 border-b border-border font-mono text-xs text-muted">
              {files.length} ไฟล์ที่เลือก
            </div>
            {files.map(f => (
              <div key={f.name} className="flex items-center gap-2 px-3 py-2 border-b border-border last:border-0">
                <FileText size={13} className="text-muted flex-shrink-0" />
                <span className="font-mono text-xs text-textdim flex-1 truncate">{f.name}</span>
                <span className="font-mono text-xs text-muted">{(f.size / 1024).toFixed(0)} KB</span>
                <button onClick={() => removeFile(f.name)}
                  className="text-muted hover:text-red-400 transition-colors"><XCircle size={13} /></button>
              </div>
            ))}
          </div>
        )}

        {/* Error */}
        {globalError && (
          <p className="font-mono text-xs text-red-400 bg-red-400/10 border border-red-400/20 rounded px-3 py-2">
            {globalError}
          </p>
        )}

        {/* Results */}
        {results && (
          <div className="card overflow-hidden">
            <div className="px-3 py-2 border-b border-border font-mono text-xs text-muted">ผลการอัพโหลด</div>
            {results.map(r => (
              <div key={r.file} className="flex items-start gap-2 px-3 py-2 border-b border-border last:border-0">
                {r.status === 'ok'
                  ? <CheckCircle size={13} className="text-accent mt-0.5 flex-shrink-0" />
                  : <XCircle    size={13} className="text-red-400 mt-0.5 flex-shrink-0" />}
                <div className="flex-1 min-w-0">
                  <span className="font-mono text-xs text-textdim block truncate">{r.file}</span>
                  {r.status === 'ok' && (
                    <span className="font-mono text-xs text-muted">
                      {r.qosType} · {r.trafficClass || '—'} · {r.experimentType}
                    </span>
                  )}
                  {r.status === 'error' && (
                    <span className="font-mono text-xs text-red-400">{r.error}</span>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}

        <button
          onClick={handleSubmit} disabled={busy}
          className="flex items-center justify-center gap-2 w-full py-2.5 rounded bg-accent/10 border border-accent/30 text-accent font-mono text-sm font-semibold hover:bg-accent/20 disabled:opacity-50 disabled:cursor-not-allowed transition-colors">
          {busy ? <><Loader2 size={14} className="animate-spin" />กำลังประมวลผล...</> : <><Upload size={14} />อัพโหลดและวิเคราะห์</>}
        </button>
      </div>
    </div>
  );
}
