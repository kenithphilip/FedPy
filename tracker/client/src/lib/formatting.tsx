import { type ReactNode } from 'react';

export const STATUSES = ['not_started','in_progress','met','not_applicable','blocked'] as const;
export type Status = typeof STATUSES[number];

export const STATUS_LABEL: Record<Status, string> = {
  not_started:    'Not started',
  in_progress:    'In progress',
  met:            'Met',
  not_applicable: 'Not applicable',
  blocked:        'Blocked',
};

export function StatusPill({ status }: { status: string }) {
  return <span className={`status-pill ${status}`}>{STATUS_LABEL[status as Status] ?? status}</span>;
}

export function KeywordPill({ kw }: { kw?: string | null }) {
  if (!kw) return null;
  return <span className={`keyword-pill ${kw}`}>{kw}</span>;
}

export function ApplicabilityPill({ applicability }: { applicability: string }) {
  const cls = applicability === '20x' ? 'x-20x' : '';
  return <span className={`applicability-pill ${cls}`}>{applicability}</span>;
}

export function ProgressBar({ counts }: { counts: Record<string, number> }) {
  const total = counts.total ?? Object.values(counts).reduce((a, b) => a + (typeof b === 'number' ? b : 0), 0);
  if (!total) return <div className="progress-bar"><span style={{ width: '100%', background: 'var(--panel-2)' }} /></div>;
  const pct = (n: number) => `${(n / total) * 100}%`;
  return (
    <div className="progress-bar" title={`${counts.met ?? 0}/${total} met`}>
      <span className="met"            style={{ width: pct(counts.met ?? 0) }} />
      <span className="in_progress"    style={{ width: pct(counts.in_progress ?? 0) }} />
      <span className="blocked"        style={{ width: pct(counts.blocked ?? 0) }} />
      <span className="not_applicable" style={{ width: pct(counts.not_applicable ?? 0) }} />
    </div>
  );
}

export function percent(counts: Record<string, number>): number {
  const total = counts.total ?? 0;
  if (!total) return 0;
  const done = (counts.met ?? 0) + (counts.not_applicable ?? 0);
  return Math.round((done / total) * 100);
}

// Highlight FRD terms in a statement by underlining them. Build a regex from the term list.
export function annotateTerms(text: string, terms: Array<{ term: string; definition: string }> | null): ReactNode {
  if (!terms?.length || !text) return text;
  // Sort longest-first to avoid partial matches
  const sorted = [...terms].sort((a, b) => b.term.length - a.term.length);
  const escaped = sorted.map((t) => t.term.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'));
  const re = new RegExp(`\\b(${escaped.join('|')})\\b`, 'g');
  const parts: ReactNode[] = [];
  let last = 0;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    if (m.index > last) parts.push(text.slice(last, m.index));
    const def = sorted.find((t) => t.term === m![1])?.definition ?? '';
    parts.push(
      <span key={`${m.index}-${m[1]}`} className="term-link" title={def}>
        {m[1]}
      </span>
    );
    last = m.index + m[0].length;
  }
  if (last < text.length) parts.push(text.slice(last));
  return <>{parts}</>;
}
