#!/usr/bin/env node
/**
 * extract-800-218A.mjs — offline one-shot extractor for LOOP-T.T5.
 *
 * Builds the canonical NIST SP 800-218A ("Secure Software Development Practices
 * for Generative AI and Dual-Use Foundation Models: An SSDF Community Profile")
 * augmentation catalogues that `core/ssdf-ai-extension.ts` reads when augmenting
 * the T.T2 satisfaction matrix for AI-bearing products.
 *
 * Architecture (matches the repo's offline-first convention — cf.
 * scripts/extract-ssdf-practices.mjs + core/ssdf-practices-catalog.ts): the two
 * published NIST PDFs live under version control at
 *   docs/sources/nist-sp-800-218A.ipd.pdf   (Initial Public Draft, 2024-04-29)
 *   docs/sources/nist-sp-800-218A.pdf        (final publication, 2024-07-26)
 * This extractor reads both committed PDFs, parses Table 1 ("SSDF Community
 * Profile for AI Model Development") deterministically, and emits two catalogue
 * JSONs plus an IPD-vs-final delta sidecar. Every task statement, R/C/N item
 * statement, priority, and informative reference is taken VERBATIM from the PDF
 * text — none is invented. The practice group names + task ids are NIST
 * published-constant identifiers.
 *
 * Reconciliation vs the T.T5 spec §2.6/§4.1: the spec assumed an augmentation
 * identifier pattern `<task>.A<n>`. The real published 800-218A uses per-task
 * Recommendation / Consideration / Note items with ids `<task>.R<n>` /
 * `<task>.C<n>` / `<task>.N<n>` (final publication §3: "'PO.1.2.R1' is the first
 * recommendation for task PO.1.2"). The catalogue schema reflects the real
 * structure. 800-218A also re-introduces the PW.3 practice + PS.1.2/PS.1.3 +
 * PO.5.3 tasks that base SSDF v1.1 does not carry; these are tagged
 * `not-part-of-ssdf-1.1` and `base_task_present:false` (they have no parent in
 * data/ssdf-800-218-v1.1.json — the aggregator treats them as new AI-specific
 * tasks with no base evidence to inherit).
 *
 * REO compliance: every field traces to the committed NIST PDF (whose SHA-256 is
 * pinned into each catalogue's provenance block). The catalogue is a vendored
 * reference (like data/ssdf-800-218-v1.1.json), lives under data/ (outside the
 * out/ signing surface), and is deterministic — re-running against the same PDFs
 * yields byte-identical JSON (emittedAt is pinned to the PDF publication date, not
 * wall-clock). On a typed failure the extractor exits non-zero and writes NOTHING.
 *
 * Run:
 *   npm run build:ssdf-ai-catalog          # rebuild both catalogues + delta
 *   tsx scripts/extract-800-218A.mjs       # same
 */
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { PDFParse } from 'pdf-parse';

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(__dirname, '..');

const IPD_PDF = 'docs/sources/nist-sp-800-218A.ipd.pdf';
const FINAL_PDF = 'docs/sources/nist-sp-800-218A.pdf';
const BASE_CATALOG = 'data/ssdf-800-218-v1.1.json';
const IPD_OUT = 'data/ssdf-800-218A-ipd.json';
const FINAL_OUT = 'data/ssdf-800-218A-final.json';
const DELTA_OUT = 'docs/sources/ssdf-800-218A-delta.json';

/** NIST published-constant: PW.3 was withdrawn from SSDF v1.1 and re-added by
 *  800-218A. Its name is not in the base catalogue, so it is pinned here (taken
 *  verbatim from the 800-218A Table 1 practice header). */
const PW3_PRACTICE_NAME =
  'Confirm the Integrity of Training, Testing, Fine-Tuning, and Aligning Data Before Use';

class ExtractError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'ExtractError';
    this.code = code;
  }
}

const TASK_RE = /^(PO|PS|PW|RV)\.\d+\.\d+:/;
const PRIORITY_RE = /^(High|Medium|Low)\b/;
const PAREN_HEADER_RE = /\(([A-Z]{2}\.\d+)\)\s*:/;
const ITEM_RE = /^([RCN])(\d+):\s*(.*)$/;
const REF_MARKER_RE = /^(AI RMF:|OWASP:|Adversarial ML:?)/;
const GROUP_BANNER_RE =
  /^(Prepare the Organization \(PO\)|Protect the Software \(PS\)|Produce Well-Secured Software \(PW\)|Respond to Vulnerabilities \(RV\))\s*$/;

const GROUP_NAMES = {
  PO: 'Prepare the Organization',
  PS: 'Protect the Software',
  PW: 'Produce Well-Secured Software',
  RV: 'Respond to Vulnerabilities',
};

function sha256Hex(buf) {
  return createHash('sha256').update(buf).digest('hex');
}

/** True for page headers / footers / running heads that must be dropped. */
function isNoiseLine(line) {
  const t = line.trim();
  if (t === '') return true;
  if (/^-{1,2}\s*\d+\s+of\s+\d+\s*-{1,2}$/.test(t)) return true; // "-- 14 of 30 --"
  // Page running-heads are tab-joined multi-column lines (e.g.
  // "NIST SP 800-218A \tSecure Software..." / "July 2024 \tGenerative AI...").
  if (/^NIST SP 800-218A\b/.test(t)) return true;
  if (t === 'Secure Software Development Practices for') return true;
  if (/^Generative AI and Dual-Use Foundation Models$/.test(t)) return true;
  if (/^(July|April) 2024\b/.test(t)) return true;
  if (/^\d{1,3}$/.test(t)) return true; // bare page number
  // Repeated Table 1 column-header row (tab-joined): "Practice \tTask \tPriority...".
  if (/^Practice\b.*\bTask\b.*\bPriority\b/.test(t)) return true;
  if (t === 'Practice' || t === 'Task' || t === 'Informative' || t === 'References') return true;
  if (/^Priority Recommendations \[R\]/.test(t)) return true;
  if (/^Notes \[N\] Specific to AI Model Development$/.test(t)) return true;
  return false;
}

/** Join wrapped PDF lines: keep a real compound hyphen (no space); else space. */
function joinWrapped(parts) {
  let out = '';
  for (const raw of parts) {
    const seg = raw.trim();
    if (seg === '') continue;
    if (out === '') out = seg;
    else if (/[A-Za-z0-9]-$/.test(out)) out += seg; // compound hyphen at line end
    else out += ' ' + seg;
  }
  return out.replace(/\s+/g, ' ').trim();
}

/** Extract + strip a trailing "[Modified from SSDF 1.1]" / "[Not part of SSDF 1.1]" tag. */
function extractTag(statement) {
  const m = statement.match(/\[(Modified from SSDF 1\.1|Not part of SSDF 1\.1)\]\s*$/);
  if (!m) return { statement: statement.trim(), tag: 'unchanged' };
  const clean = statement.slice(0, m.index).trim();
  const tag = m[1] === 'Modified from SSDF 1.1' ? 'modified' : 'not-part-of-ssdf-1.1';
  return { statement: clean, tag };
}

/**
 * Parse Table 1 of an 800-218A PDF into practices → tasks → R/C/N items.
 * Task-id-anchored: each task block runs from its `<TASK>:` line to just before
 * the next structural boundary (next task, a practice-header block, a group
 * banner, or EOF). Within a block the priority keyword line splits the task
 * statement (above) from the tab-separated Recommendations column + Informative
 * References column (below); the reference column begins at the first
 * "AI RMF:"/"OWASP:"/"Adversarial ML" marker.
 */
function parseTable(rawText) {
  const lines = rawText.split('\n').filter((l) => !isNoiseLine(l));
  const n = lines.length;

  // A practice-name block begins 1-2 lines before a "(PX.n):" paren header.
  const isParenHeaderStartAt = (i) => {
    if (i >= n) return false;
    if (TASK_RE.test(lines[i]) || PRIORITY_RE.test(lines[i])) return false;
    for (let k = 0; k <= 2 && i + k < n; k++) {
      if (PAREN_HEADER_RE.test(lines[i + k])) return true;
    }
    return false;
  };

  const tasksByPractice = new Map(); // practiceId -> Map<taskId, task>
  const orderedPractices = []; // practiceId in first-seen order

  const recordTask = (task) => {
    const practiceId = task.task_id.split('.').slice(0, 2).join('.');
    if (!tasksByPractice.has(practiceId)) {
      tasksByPractice.set(practiceId, new Map());
      orderedPractices.push(practiceId);
    }
    tasksByPractice.get(practiceId).set(task.task_id, task);
  };

  let i = 0;
  while (i < n) {
    const line = lines[i];
    const taskMatch = line.match(/^((PO|PS|PW|RV)\.\d+\.\d+):\s*(.*)$/);
    if (!taskMatch) {
      i++;
      continue;
    }
    const taskId = taskMatch[1];
    const stmtParts = [taskMatch[3]];

    // Gather statement lines until the priority line (or a structural boundary).
    let j = i + 1;
    while (j < n && !PRIORITY_RE.test(lines[j]) && !TASK_RE.test(lines[j]) && !isParenHeaderStartAt(j) && !GROUP_BANNER_RE.test(lines[j])) {
      stmtParts.push(lines[j]);
      j++;
    }
    const { statement, tag } = extractTag(joinWrapped(stmtParts));

    let priority = null;
    const items = [];
    const refParts = [];

    if (j < n && PRIORITY_RE.test(lines[j])) {
      const pm = lines[j].match(PRIORITY_RE);
      priority = pm[1];
      // Column content on the priority line: tab-separated fields after priority.
      const afterPriority = lines[j].slice(pm[0].length);
      const colChunks = afterPriority.split('\t').map((s) => s.trim()).filter((s) => s !== '');
      j++;

      // Feed the priority-line column chunks, then subsequent wrapped lines, into
      // a rec/ref state machine that stops at the next structural boundary.
      const feed = [...colChunks];
      while (j < n && !TASK_RE.test(lines[j]) && !isParenHeaderStartAt(j) && !GROUP_BANNER_RE.test(lines[j])) {
        feed.push(lines[j]);
        j++;
      }

      let mode = 'rec';
      let current = null;
      const flush = () => {
        if (current) {
          items.push(current);
          current = null;
        }
      };
      for (const chunk of feed) {
        const c = chunk.trim();
        if (c === '') continue;
        const im = c.match(ITEM_RE);
        // A row can span a page break, which interleaves a reference-column chunk
        // between recommendation items. So an item marker always re-enters rec
        // mode (recovering R2/C1 that follow a mid-row ref chunk); a reference
        // marker enters ref mode only when NOT starting a new item.
        if (im) {
          flush();
          mode = 'rec';
          current = { type: im[1], num: Number(im[2]), parts: [im[3]] };
          continue;
        }
        if (REF_MARKER_RE.test(c)) {
          flush();
          mode = 'ref';
          refParts.push(c);
          continue;
        }
        if (mode === 'ref') {
          refParts.push(c);
          continue;
        }
        // rec mode, no marker
        if (/^No additions to SSDF 1\.1/.test(c)) {
          continue; // sentinel: the task carries no AI-specific items
        }
        if (current) current.parts.push(c);
        // A stray non-item rec line with no current item is ignored (defensive).
      }
      flush();
    }

    recordTask({
      task_id: taskId,
      task_statement: statement,
      ssdf_1_1_tag: tag,
      priority,
      no_additions: items.length === 0,
      _items: items,
      informative_references: splitRefs(joinWrapped(refParts)),
    });

    i = j;
  }

  return { tasksByPractice, orderedPractices };
}

/** Split an informative-reference blob into per-source strings. */
function splitRefs(blob) {
  if (!blob) return [];
  const segments = blob
    .split(/(?=AI RMF:|OWASP:|Adversarial ML:?)/)
    .map((s) => s.trim())
    .filter((s) => s !== '');
  return segments.length > 0 ? segments : (blob.trim() ? [blob.trim()] : []);
}

/** Assemble the catalogue object from parsed practices, joining base names. */
function buildCatalogue(parsed, version, publicationDate, sourcePdfSha256, baseTaskIds) {
  const { tasksByPractice, orderedPractices } = parsed;
  const practiceNames = basePracticeNames();

  const practices = [];
  let augmentationCount = 0;
  let taskCount = 0;

  // Deterministic practice ordering (PO, PS, PW, RV by number).
  const sortedPractices = [...orderedPractices].sort(comparePracticeId);

  for (const practiceId of sortedPractices) {
    const group = practiceId.slice(0, 2);
    const name = practiceId === 'PW.3' ? PW3_PRACTICE_NAME : (practiceNames[practiceId] ?? '');
    const taskMap = tasksByPractice.get(practiceId);
    const tasks = [...taskMap.values()].sort((a, b) => compareTaskId(a.task_id, b.task_id));

    const outTasks = tasks.map((t) => {
      const basePresent = baseTaskIds.has(t.task_id);
      // A task absent from base SSDF v1.1 cannot be "unchanged"; when the inline
      // "[Not part of SSDF 1.1]" tag was displaced by a mid-row page break, infer
      // it from base-absence so the tag is never misleadingly "unchanged".
      let tag = t.ssdf_1_1_tag;
      if (!basePresent && tag === 'unchanged') tag = 'not-part-of-ssdf-1.1';
      const augmentations = t._items.map((it) => {
        augmentationCount++;
        return {
          augmentation_id: `${t.task_id}.${it.type}${it.num}`,
          parent_task_id: t.task_id,
          item_type: it.type, // 'R' | 'C' | 'N'
          statement: joinWrapped(it.parts),
          notes: '',
          informative_references: t.informative_references,
          // 800-218A does not tag items by AI mode; the whole Profile applies to
          // both generative-AI and dual-use foundation models (spec §11 default).
          applies_to: ['both'],
        };
      });
      taskCount++;
      return {
        task_id: t.task_id,
        task_statement: t.task_statement,
        ssdf_1_1_tag: tag,
        base_task_present: basePresent,
        priority: t.priority,
        no_additions: t.no_additions,
        informative_references: t.informative_references,
        augmentations,
      };
    });

    practices.push({
      practice_id: practiceId,
      practice_group: group,
      practice_group_name: GROUP_NAMES[group],
      practice_name: name,
      tasks: outTasks,
    });
  }

  return {
    schema_version: '1.0',
    version, // 'IPD' | 'final'
    publication: {
      sp: '800-218A',
      title:
        'Secure Software Development Practices for Generative AI and Dual-Use Foundation Models: An SSDF Community Profile',
      publication_date: publicationDate,
    },
    sha256_source_pdf: sourcePdfSha256,
    statistics: {
      practice_count: practices.length,
      task_count: taskCount,
      augmentation_count: augmentationCount,
      new_ai_task_count: practices.reduce(
        (a, p) => a + p.tasks.filter((t) => !t.base_task_present).length,
        0,
      ),
    },
    practices,
    provenance: {
      emitter: 'scripts/extract-800-218A.mjs',
      emittedAt: publicationDate, // pinned (deterministic re-runs)
      sourceCalls: [`pdf-parse:${version === 'IPD' ? IPD_PDF : FINAL_PDF}`],
      sourceDigests: [
        { kind: 'nist-pdf', path: version === 'IPD' ? IPD_PDF : FINAL_PDF, sha256: sourcePdfSha256 },
        { kind: 'ssdf-base-catalog', path: BASE_CATALOG, sha256: 'join-key-only' },
      ],
      signingKeyId: 'unsigned-vendored-reference',
    },
  };
}

function basePracticeNames() {
  const base = JSON.parse(readFileSync(resolve(REPO_ROOT, BASE_CATALOG), 'utf8'));
  const names = {};
  for (const p of base.practices) names[p.id] = p.name;
  return names;
}

function comparePracticeId(a, b) {
  const [ga, na] = [a.slice(0, 2), Number(a.split('.')[1])];
  const [gb, nb] = [b.slice(0, 2), Number(b.split('.')[1])];
  const order = { PO: 0, PS: 1, PW: 2, RV: 3 };
  if (order[ga] !== order[gb]) return order[ga] - order[gb];
  return na - nb;
}

function compareTaskId(a, b) {
  const pa = a.split('.').map(Number).slice(1);
  const pb = b.split('.').map(Number).slice(1);
  return pa[0] - pb[0] || pa[1] - pb[1];
}

/** Validate a parsed catalogue against structural + base-catalogue invariants. */
function validateCatalogue(cat, baseTaskIds) {
  const groups = new Set(cat.practices.map((p) => p.practice_group));
  for (const g of groups) {
    if (!['PO', 'PS', 'PW', 'RV'].includes(g)) {
      throw new ExtractError('ERR_218A_BAD_GROUP', `unexpected practice group "${g}"`);
    }
  }
  if (cat.practices.length < 4) {
    throw new ExtractError('ERR_218A_TOO_FEW_PRACTICES', `only ${cat.practices.length} practices parsed (expected >= the 4 SSDF groups' practices)`);
  }
  let baseMisses = 0;
  for (const p of cat.practices) {
    for (const t of p.tasks) {
      if (!t.task_statement) {
        throw new ExtractError('ERR_218A_EMPTY_TASK', `task ${t.task_id} has an empty statement`);
      }
      for (const a of t.augmentations) {
        if (!a.statement) {
          throw new ExtractError('ERR_218A_EMPTY_AUG', `augmentation ${a.augmentation_id} has an empty statement`);
        }
      }
      if (t.base_task_present && !baseTaskIds.has(t.task_id)) baseMisses++;
    }
  }
  if (baseMisses > 0) throw new ExtractError('ERR_218A_BASE_JOIN', `${baseMisses} tasks flagged base-present but absent from ${BASE_CATALOG}`);
}

/** IPD-vs-final delta by augmentation id. */
function computeDelta(ipd, final) {
  const indexById = (cat) => {
    const m = new Map();
    for (const p of cat.practices) {
      for (const t of p.tasks) {
        for (const a of t.augmentations) m.set(a.augmentation_id, a);
      }
    }
    return m;
  };
  const ipdMap = indexById(ipd);
  const finalMap = indexById(final);
  const added = [];
  const removed = [];
  const restated = [];
  const renamed = [];
  for (const [id, a] of finalMap) {
    if (!ipdMap.has(id)) {
      added.push({ augmentation_id: id, final_text: a.statement });
    } else {
      const b = ipdMap.get(id);
      if (b.parent_task_id !== a.parent_task_id) {
        renamed.push({ augmentation_id: id, ipd_parent: b.parent_task_id, final_parent: a.parent_task_id });
      } else if (norm(b.statement) !== norm(a.statement)) {
        restated.push({ augmentation_id: id, ipd_text: b.statement, final_text: a.statement });
      }
    }
  }
  for (const [id, a] of ipdMap) {
    if (!finalMap.has(id)) removed.push({ augmentation_id: id, ipd_text: a.statement });
  }
  return {
    schema_version: '1.0',
    generated_from: { ipd: IPD_OUT, final: FINAL_OUT },
    ipd_augmentation_count: ipdMap.size,
    final_augmentation_count: finalMap.size,
    added,
    removed,
    restated,
    renamed,
  };
}

function norm(s) {
  return s.replace(/\s+/g, ' ').trim().toLowerCase();
}

function extractOne(pdfRel, version, publicationDate, baseTaskIds) {
  const abs = resolve(REPO_ROOT, pdfRel);
  if (!existsSync(abs)) {
    throw new ExtractError('ERR_218A_SOURCE_MISSING', `source PDF missing: ${pdfRel}. Download from NIST CSRC before running the extractor.`);
  }
  const buf = readFileSync(abs);
  const sha = sha256Hex(buf);
  return { buf, sha, abs, pdfRel, version, publicationDate };
}

async function main() {
  const base = JSON.parse(readFileSync(resolve(REPO_ROOT, BASE_CATALOG), 'utf8'));
  const baseTaskIds = new Set();
  for (const p of base.practices) for (const t of p.tasks) baseTaskIds.add(t.id);

  const sources = [
    extractOne(IPD_PDF, 'IPD', '2024-04-29', baseTaskIds),
    extractOne(FINAL_PDF, 'final', '2024-07-26', baseTaskIds),
  ];

  const catalogues = {};
  for (const s of sources) {
    const parser = new PDFParse({ data: new Uint8Array(s.buf) });
    const parsed = parseTable((await parser.getText()).text);
    const cat = buildCatalogue(parseToStructured(parsed), s.version, s.publicationDate, s.sha, baseTaskIds);
    validateCatalogue(cat, baseTaskIds);
    catalogues[s.version] = cat;
    // Pin the .sha256 sibling for the committed source PDF.
    writeFileSync(resolve(REPO_ROOT, `${s.pdfRel}.sha256`), `${s.sha}  ${s.pdfRel.split('/').pop()}\n`);
  }

  const delta = computeDelta(catalogues.IPD, catalogues.final);

  writeFileSync(resolve(REPO_ROOT, IPD_OUT), JSON.stringify(catalogues.IPD, null, 2) + '\n');
  writeFileSync(resolve(REPO_ROOT, FINAL_OUT), JSON.stringify(catalogues.final, null, 2) + '\n');
  writeFileSync(resolve(REPO_ROOT, DELTA_OUT), JSON.stringify(delta, null, 2) + '\n');

  for (const v of ['IPD', 'final']) {
    const c = catalogues[v];
    console.log(
      `[extract-800-218A] ${v}: ${c.statistics.practice_count} practices, ${c.statistics.task_count} tasks, ` +
      `${c.statistics.augmentation_count} R/C/N items, ${c.statistics.new_ai_task_count} new AI tasks. sha256=${c.sha256_source_pdf.slice(0, 12)}…`,
    );
  }
  console.log(
    `[extract-800-218A] delta: +${delta.added.length} added, -${delta.removed.length} removed, ` +
    `${delta.restated.length} restated, ${delta.renamed.length} renamed.`,
  );
}

// buildCatalogue expects { tasksByPractice, orderedPractices }; parseTable already
// returns that shape. This indirection keeps the call site explicit.
function parseToStructured(parsed) {
  return parsed;
}

main().catch((e) => {
  if (e instanceof ExtractError) {
    console.error(`[extract-800-218A] FAILED [${e.code}]: ${e.message}`);
    process.exit(2);
  }
  console.error(`[extract-800-218A] FAILED: ${e?.stack ?? e?.message ?? e}`);
  process.exit(1);
});
