import * as fs from 'fs';
import * as path from 'path';

export type LifecycleStatus =
  | 'new'
  | 'confirmed'
  | 'acknowledged'
  | 'fix_in_progress'
  | 'fixed'
  | 'verified'
  | 'false_positive'
  | 'accepted_risk';

export interface FindingLifecycle {
  findingId: string;
  status: LifecycleStatus;
  detectedAt: string;
  confirmedAt?: string;
  fixedAt?: string;
  verifiedAt?: string;
  notes: string[];
}

export interface LifecycleStore {
  findings: Record<string, FindingLifecycle>;
}

export function loadLifecycleStore(rootPath: string): LifecycleStore {
  const storePath = path.join(rootPath, '.lui-lifecycle.json');
  if (fs.existsSync(storePath)) {
    try {
      return JSON.parse(fs.readFileSync(storePath, 'utf-8'));
    } catch { /* ignore */ }
  }
  return { findings: {} };
}

export function saveLifecycleStore(rootPath: string, store: LifecycleStore): void {
  const storePath = path.join(rootPath, '.lui-lifecycle.json');
  fs.writeFileSync(storePath, JSON.stringify(store, null, 2), 'utf-8');
}

export function updateFindingStatus(
  store: LifecycleStore,
  findingId: string,
  status: LifecycleStatus,
  note?: string
): LifecycleStore {
  const now = new Date().toISOString();
  const existing = store.findings[findingId];

  if (!existing) {
    store.findings[findingId] = {
      findingId,
      status,
      detectedAt: now,
      notes: note ? [note] : [],
    };
  } else {
    existing.status = status;
    if (status === 'confirmed' && !existing.confirmedAt) existing.confirmedAt = now;
    if (status === 'fixed' && !existing.fixedAt) existing.fixedAt = now;
    if (status === 'verified' && !existing.verifiedAt) existing.verifiedAt = now;
    if (note) existing.notes.push(note);
  }

  return store;
}

export function initializeLifecycle(store: LifecycleStore, findingIds: string[]): LifecycleStore {
  const now = new Date().toISOString();
  for (const id of findingIds) {
    if (!store.findings[id]) {
      store.findings[id] = {
        findingId: id,
        status: 'new',
        detectedAt: now,
        notes: [],
      };
    }
  }
  return store;
}

export function getLifecycleHistory(store: LifecycleStore, findingId: string): FindingLifecycle | null {
  return store.findings[findingId] || null;
}

export function formatLifecycle(lifecycle: FindingLifecycle): string {
  const lines: string[] = [];
  const statusIcons: Record<LifecycleStatus, string> = {
    new: '●',
    confirmed: '◉',
    acknowledged: '○',
    fix_in_progress: '◐',
    fixed: '✓',
    verified: '★★',
    false_positive: '✗',
    accepted_risk: '—',
  };

  lines.push(`Status: ${statusIcons[lifecycle.status]} ${lifecycle.status.toUpperCase()}`);
  lines.push(`Detected: ${formatDate(lifecycle.detectedAt)}`);
  if (lifecycle.confirmedAt) lines.push(`Confirmed: ${formatDate(lifecycle.confirmedAt)}`);
  if (lifecycle.fixedAt) lines.push(`Fixed: ${formatDate(lifecycle.fixedAt)}`);
  if (lifecycle.verifiedAt) lines.push(`Verified: ${formatDate(lifecycle.verifiedAt)}`);

  if (lifecycle.notes.length > 0) {
    lines.push('Notes:');
    for (const note of lifecycle.notes) {
      lines.push(`  - ${note}`);
    }
  }

  return lines.join('\n');
}

function formatDate(iso: string): string {
  return new Date(iso).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
}
