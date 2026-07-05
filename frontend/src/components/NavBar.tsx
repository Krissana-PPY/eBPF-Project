'use client';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { Activity, Upload, Database } from 'lucide-react';
import clsx from 'clsx';

const links = [
  { href: '/',       icon: Database, label: 'Datasets'  },
  { href: '/upload', icon: Upload,   label: 'Upload'    },
];

export default function NavBar() {
  const path = usePathname();
  return (
    <header className="sticky top-0 z-50 bg-bg/90 backdrop-blur border-b border-border">
      <div className="max-w-6xl mx-auto px-4 h-12 flex items-center gap-4">
        <Link href="/" className="flex items-center gap-2 mr-4">
          <Activity size={16} className="text-accent" />
          <span className="font-mono text-sm font-semibold text-textdim tracking-wide">
            eBPF QoS Research
          </span>
        </Link>
        <nav className="flex gap-1">
          {links.map(({ href, icon: Icon, label }) => (
            <Link key={href} href={href}
              className={clsx(
                'flex items-center gap-1.5 px-3 py-1 rounded font-mono text-xs transition-colors',
                path === href
                  ? 'bg-accent/10 text-accent'
                  : 'text-muted hover:text-textdim hover:bg-surface'
              )}>
              <Icon size={13} />
              {label}
            </Link>
          ))}
        </nav>
      </div>
    </header>
  );
}
