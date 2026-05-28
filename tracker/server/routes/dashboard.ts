import { Hono } from 'hono';
import { db } from '../db.ts';
import { requireAuth } from '../auth.ts';

export const dashboardRoutes = new Hono();
dashboardRoutes.use('*', requireAuth);

const STATUSES = ['not_started','in_progress','met','not_applicable','blocked'] as const;

function emptyCounts(): Record<string, number> {
  const o: Record<string, number> = {};
  for (const s of STATUSES) o[s] = 0;
  o.total = 0;
  return o;
}

dashboardRoutes.get('/dashboard', (c) => {
  // Overall counts
  const overall = {
    requirements: emptyCounts(),
    indicators: emptyCounts(),
  };

  const reqRows = db().prepare(`
    SELECT COALESCE(s.status,'not_started') AS status, COUNT(*) AS c
    FROM requirements r
    LEFT JOIN item_state s ON s.item_id = r.id AND s.item_type = 'requirement'
    GROUP BY COALESCE(s.status,'not_started')
  `).all() as any[];
  for (const r of reqRows) { overall.requirements[r.status] = r.c; overall.requirements.total! += r.c; }

  const indRows = db().prepare(`
    SELECT COALESCE(s.status,'not_started') AS status, COUNT(*) AS c
    FROM indicators i
    LEFT JOIN item_state s ON s.item_id = i.id AND s.item_type = 'indicator'
    GROUP BY COALESCE(s.status,'not_started')
  `).all() as any[];
  for (const r of indRows) { overall.indicators[r.status] = r.c; overall.indicators.total! += r.c; }

  // By process (requirements)
  const byProcess = db().prepare(`
    SELECT r.process_id, p.name AS process_name, COALESCE(s.status,'not_started') AS status, COUNT(*) AS c
    FROM requirements r
    JOIN processes p ON p.id = r.process_id
    LEFT JOIN item_state s ON s.item_id = r.id AND s.item_type = 'requirement'
    GROUP BY r.process_id, COALESCE(s.status,'not_started')
    ORDER BY r.process_id
  `).all() as any[];
  const processMap: Record<string, { id: string; name: string; counts: Record<string, number> }> = {};
  for (const r of byProcess) {
    if (!processMap[r.process_id]) processMap[r.process_id] = { id: r.process_id, name: r.process_name, counts: emptyCounts() };
    processMap[r.process_id]!.counts[r.status] = r.c;
    processMap[r.process_id]!.counts.total! += r.c;
  }

  // By KSI domain
  const byDomain = db().prepare(`
    SELECT i.domain_id, d.name AS domain_name, COALESCE(s.status,'not_started') AS status, COUNT(*) AS c
    FROM indicators i
    JOIN ksi_domains d ON d.id = i.domain_id
    LEFT JOIN item_state s ON s.item_id = i.id AND s.item_type = 'indicator'
    GROUP BY i.domain_id, COALESCE(s.status,'not_started')
    ORDER BY i.domain_id
  `).all() as any[];
  const domainMap: Record<string, { id: string; name: string; counts: Record<string, number> }> = {};
  for (const r of byDomain) {
    if (!domainMap[r.domain_id]) domainMap[r.domain_id] = { id: r.domain_id, name: r.domain_name, counts: emptyCounts() };
    domainMap[r.domain_id]!.counts[r.status] = r.c;
    domainMap[r.domain_id]!.counts.total! += r.c;
  }

  // Next 10 to tackle: not_started, ordered by primary_key_word (MUST first)
  const nextUp = db().prepare(`
    SELECT r.id, r.process_id, r.name, r.statement, r.primary_key_word, r.applicability
    FROM requirements r
    LEFT JOIN item_state s ON s.item_id = r.id AND s.item_type = 'requirement'
    WHERE COALESCE(s.status,'not_started') = 'not_started'
    ORDER BY
      CASE r.primary_key_word
        WHEN 'MUST' THEN 0
        WHEN 'SHOULD' THEN 1
        WHEN 'MAY' THEN 2
        ELSE 3
      END,
      CASE r.applicability WHEN '20x' THEN 0 WHEN 'both' THEN 1 ELSE 2 END,
      r.process_id, r.id
    LIMIT 10
  `).all();

  return c.json({
    overall,
    by_process: Object.values(processMap),
    by_domain: Object.values(domainMap),
    next_up: nextUp,
  });
});

// NIST 800-53 crosswalk: control -> indicators that reference it
dashboardRoutes.get('/crosswalk', (c) => {
  const rows = db().prepare(`
    SELECT
      c.id AS control_id,
      c.family,
      i.id AS indicator_id,
      i.name AS indicator_name,
      d.id AS domain_id,
      d.name AS domain_name,
      COALESCE(s.status,'not_started') AS status
    FROM controls c
    JOIN indicator_controls ic ON ic.control_id = c.id
    JOIN indicators i ON i.id = ic.indicator_id
    JOIN ksi_domains d ON d.id = i.domain_id
    LEFT JOIN item_state s ON s.item_id = i.id AND s.item_type = 'indicator'
    ORDER BY c.family, c.id, i.id
  `).all() as any[];

  // Group by control
  const map: Record<string, {
    control_id: string;
    family: string;
    indicators: Array<{ id: string; name: string; domain_id: string; domain_name: string; status: string }>;
    status_counts: Record<string, number>;
  }> = {};
  for (const r of rows) {
    if (!map[r.control_id]) {
      map[r.control_id] = {
        control_id: r.control_id,
        family: r.family,
        indicators: [],
        status_counts: emptyCounts(),
      };
    }
    const c2 = map[r.control_id]!;
    c2.indicators.push({
      id: r.indicator_id,
      name: r.indicator_name,
      domain_id: r.domain_id,
      domain_name: r.domain_name,
      status: r.status,
    });
    c2.status_counts[r.status] = (c2.status_counts[r.status] ?? 0) + 1;
    c2.status_counts.total = (c2.status_counts.total ?? 0) + 1;
  }
  return c.json({ controls: Object.values(map) });
});
