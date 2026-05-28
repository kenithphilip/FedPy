import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { db } from './db.ts';

const FRMR_PATH = process.env.FRMR_PATH ?? resolve(process.cwd(), '../docs/FRMR.documentation.json');

type Json = any;

function loadFrmr(): Json {
  const raw = readFileSync(FRMR_PATH, 'utf8');
  return JSON.parse(raw);
}

function ingest() {
  const frmr = loadFrmr();
  const d = db();

  console.log(`Loaded FRMR ${frmr?.info?.version ?? '?'} (updated ${frmr?.info?.last_updated ?? '?'}) from ${FRMR_PATH}`);

  const tx = d.transaction(() => {
    // Reset FRMR-derived tables (state/users/sessions/audit_log left untouched).
    d.exec(`
      DELETE FROM indicator_controls;
      DELETE FROM controls;
      DELETE FROM indicators;
      DELETE FROM ksi_domains;
      DELETE FROM requirements;
      DELETE FROM process_labels;
      DELETE FROM processes;
      DELETE FROM definitions;
    `);

    // ---- FRD: definitions ----
    const insertDef = d.prepare(`
      INSERT INTO definitions (id, term, definition, alts_json, fka)
      VALUES (@id, @term, @definition, @alts_json, @fka)
    `);
    const frdBucket = frmr?.FRD?.data?.both ?? {};
    let frdCount = 0;
    for (const [id, def] of Object.entries<Json>(frdBucket)) {
      insertDef.run({
        id,
        term: String(def.term ?? id),
        definition: String(def.definition ?? ''),
        alts_json: JSON.stringify(def.alts ?? []),
        fka: def.fka ?? null,
      });
      frdCount++;
    }

    // ---- FRR: processes, labels, requirements ----
    const insertProc = d.prepare(`
      INSERT INTO processes (id, kind, short_name, name, web_name, info_json)
      VALUES (@id, @kind, @short_name, @name, @web_name, @info_json)
    `);
    const insertLabel = d.prepare(`
      INSERT INTO process_labels (process_id, label_key, label_name)
      VALUES (@process_id, @label_key, @label_name)
    `);
    const insertReq = d.prepare(`
      INSERT INTO requirements (
        id, process_id, applicability, actor_label, name, statement, primary_key_word,
        terms_json, affects_json, following_info_json, examples_json, note, fka,
        timeframe_type, timeframe_num, raw_json
      ) VALUES (
        @id, @process_id, @applicability, @actor_label, @name, @statement, @primary_key_word,
        @terms_json, @affects_json, @following_info_json, @examples_json, @note, @fka,
        @timeframe_type, @timeframe_num, @raw_json
      )
    `);

    let procCount = 0;
    let reqCount = 0;
    const frrProcesses = frmr?.FRR ?? {};
    for (const [pid, p] of Object.entries<Json>(frrProcesses)) {
      const info = p?.info ?? {};
      insertProc.run({
        id: pid,
        kind: 'FRR',
        short_name: info.short_name ?? pid,
        name: info.name ?? pid,
        web_name: info.web_name ?? null,
        info_json: JSON.stringify(info),
      });
      procCount++;

      const labels: Record<string, string> = info.labels ?? {};
      for (const [labelKey, labelName] of Object.entries(labels)) {
        insertLabel.run({
          process_id: pid,
          label_key: labelKey,
          label_name: String(labelName),
        });
      }

      const data = p?.data ?? {};
      for (const applicability of Object.keys(data) as Array<'20x' | 'rev5' | 'both'>) {
        const labelBucket = data[applicability] ?? {};
        for (const [labelKey, reqs] of Object.entries<Json>(labelBucket)) {
          for (const [rid, r] of Object.entries<Json>(reqs)) {
            if (typeof r !== 'object' || r === null) continue;

            // varies_by_level: store JSON, surface a placeholder statement
            const variesByLevel = r.varies_by_level;
            const statement = r.statement
              ?? (variesByLevel ? '(varies by impact level — see details)' : '');

            insertReq.run({
              id: rid,
              process_id: pid,
              applicability,
              actor_label: labelKey,
              name: r.name ?? null,
              statement: String(statement),
              primary_key_word: r.primary_key_word ?? null,
              terms_json: JSON.stringify(r.terms ?? []),
              affects_json: JSON.stringify(r.affects ?? []),
              following_info_json: JSON.stringify(r.following_information ?? []),
              examples_json: JSON.stringify(r.examples ?? []),
              note: r.note ?? null,
              fka: r.fka ?? (Array.isArray(r.fkas) ? JSON.stringify(r.fkas) : null),
              timeframe_type: r.timeframe_type ?? null,
              timeframe_num: typeof r.timeframe_num === 'number' ? r.timeframe_num : null,
              raw_json: JSON.stringify(r),
            });
            reqCount++;
          }
        }
      }
    }

    // ---- KSI: domains, indicators, controls ----
    const insertDomain = d.prepare(`
      INSERT INTO ksi_domains (id, short_name, name, web_name, theme)
      VALUES (@id, @short_name, @name, @web_name, @theme)
    `);
    const insertInd = d.prepare(`
      INSERT INTO indicators (id, domain_id, name, statement, fka, raw_json)
      VALUES (@id, @domain_id, @name, @statement, @fka, @raw_json)
    `);
    const insertCtrl = d.prepare(`
      INSERT OR IGNORE INTO controls (id, family) VALUES (@id, @family)
    `);
    const insertIndCtrl = d.prepare(`
      INSERT INTO indicator_controls (indicator_id, control_id)
      VALUES (@indicator_id, @control_id)
    `);

    let domCount = 0;
    let indCount = 0;
    let ctrlCount = 0;
    const ksi = frmr?.KSI ?? {};
    for (const [did, dom] of Object.entries<Json>(ksi)) {
      if (did === 'info') continue;
      insertDomain.run({
        id: did,
        short_name: dom.short_name ?? did,
        name: dom.name ?? did,
        web_name: dom.web_name ?? null,
        theme: dom.theme ?? null,
      });
      domCount++;

      const indicators = dom.indicators ?? {};
      for (const [iid, ind] of Object.entries<Json>(indicators)) {
        insertInd.run({
          id: iid,
          domain_id: did,
          name: ind.name ?? null,
          statement: String(ind.statement ?? ''),
          fka: ind.fka ?? null,
          raw_json: JSON.stringify(ind),
        });
        indCount++;

        for (const ctrl of (ind.controls ?? []) as string[]) {
          const family = ctrl.split('-')[0] ?? ctrl;
          insertCtrl.run({ id: ctrl, family });
          insertIndCtrl.run({ indicator_id: iid, control_id: ctrl });
        }
      }
    }
    // FedRAMP 20x KSI count is 63: 60 outcome-level KSIs (above) + 3 meta-rule
    // KSIs that live in FRR.KSI under the CSX label ("20x-Specific Provider
    // Responsibilities"). Surface them as a 12th KSI domain so the dashboard
    // total matches FedRAMP's published 63 count.
    const frrKsi = frmr?.FRR?.KSI;
    const csxEntries = frrKsi?.data?.['20x']?.CSX as Record<string, Json> | undefined;
    if (csxEntries && Object.keys(csxEntries).length > 0) {
      const csxLabelInfo = frrKsi?.info?.labels?.CSX ?? {};
      insertDomain.run({
        id: 'CSX',
        short_name: 'CSX',
        name: csxLabelInfo.name ?? '20x-Specific Provider Responsibilities',
        web_name: 'csx',
        theme: csxLabelInfo.description ?? null,
      });
      domCount++;

      for (const [iid, ind] of Object.entries<Json>(csxEntries)) {
        const stmt = ind.statement
          ?? (ind.varies_by_level ? '(varies by impact level — see details)' : '');
        insertInd.run({
          id: iid,
          domain_id: 'CSX',
          name: ind.name ?? null,
          statement: String(stmt),
          fka: ind.fka ?? (Array.isArray(ind.fkas) ? JSON.stringify(ind.fkas) : null),
          raw_json: JSON.stringify(ind),
        });
        indCount++;
      }
    }

    ctrlCount = (d.prepare('SELECT COUNT(*) AS c FROM controls').get() as any).c;

    // Metadata
    const setMeta = d.prepare(`
      INSERT INTO frmr_meta (key, value) VALUES (@key, @value)
      ON CONFLICT(key) DO UPDATE SET value = excluded.value
    `);
    setMeta.run({ key: 'version', value: String(frmr?.info?.version ?? '') });
    setMeta.run({ key: 'last_updated', value: String(frmr?.info?.last_updated ?? '') });
    setMeta.run({ key: 'ingested_at', value: new Date().toISOString() });

    console.log(`  Definitions: ${frdCount}`);
    console.log(`  Processes:   ${procCount}`);
    console.log(`  Requirements: ${reqCount}`);
    console.log(`  KSI Domains: ${domCount}`);
    console.log(`  Indicators:  ${indCount}`);
    console.log(`  NIST controls referenced: ${ctrlCount}`);
  });

  tx();
  console.log('Ingest complete.');
}

ingest();
