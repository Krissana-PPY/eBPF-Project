import clsx from 'clsx';

interface Props {
  label:     string;
  value:     string | number;
  unit?:     string;
  sub?:      string;
  badge?:    string;
  variant?:  'accent' | 'htb' | 'noqos';
}

const variantMap = {
  accent: { top: 'bg-accent', val: 'text-accent',  label: 'text-accent' },
  htb:    { top: 'bg-htb',   val: 'text-htb',     label: 'text-htb'   },
  noqos:  { top: 'bg-noqos', val: 'text-noqos',   label: 'text-noqos' },
};

export default function MetricCard({ label, value, unit, sub, badge, variant = 'noqos' }: Props) {
  const v = variantMap[variant];
  return (
    <div className="card relative overflow-hidden">
      <div className={clsx('absolute top-0 left-0 right-0 h-0.5', v.top)} />
      <div className="p-4 pt-5">
        <div className={clsx('font-mono text-xs font-bold uppercase tracking-widest mb-2', v.label)}>{label}</div>
        <div className={clsx('font-mono font-bold leading-none', v.val)} style={{ fontSize: '2.4rem' }}>
          {typeof value === 'number' ? value.toLocaleString() : value}
        </div>
        {unit && <div className="font-mono text-xs text-muted mt-1">{unit}</div>}
        {sub   && <div className="text-xs text-muted mt-2">{sub}</div>}
        {badge && (
          <span className="mt-2 inline-block font-mono text-xs font-bold px-1.5 py-0.5 rounded bg-accent/10 text-accent border border-accent/30">
            {badge}
          </span>
        )}
      </div>
    </div>
  );
}
