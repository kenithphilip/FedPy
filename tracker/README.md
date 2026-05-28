# FedRAMP 20x Tracker

A local, multi-user web dashboard that ingests the
[FedRAMP Machine-Readable](https://github.com/FedRAMP/docs)
(`FRMR.documentation.json`) source of truth and lets your team track
implementation status against every FedRAMP 20x requirement and Key
Security Indicator (KSI).

It is **not** a fork of the FedRAMP docs — it sits next to a clone of the
upstream repo and re-ingests on demand, preserving the status, owner,
notes, and evidence you've entered.

## What you get

- **Dashboard** — % done, status counts, "next 10 to tackle" (MUSTs first)
- **Gap analysis** — every not-started item grouped by Process / KSI Domain
- **Requirements browser** — filter by process, applicability (20x / Rev5 / both), actor label, status, owner, free-text
- **KSI browser** — filter by domain, status, free-text
- **Item detail** — full statement (with FRD term tooltips), RFC 2119 keyword, following-information list, examples, varies-by-level handling, plus your editable status / owner / notes / evidence / last-reviewed fields
- **NIST 800-53 crosswalk** — for each control referenced by a KSI, the indicators that satisfy it and their current status — useful when mapping 20x against an existing Rev5 / NIST baseline
- **Definitions (FRD) browser**
- **CSV / JSON export** — your full tracker state for spreadsheets or external GRC ingest
- **Multi-user** with sessions, per-item audit log, role-based admin gating of new sign-ups

## Stack

- Node 24+
- Hono + better-sqlite3 (server)
- React 18 + Vite + TanStack Query + React Router (client)
- TypeScript end-to-end, no Bun required
- SQLite file at `data/tracker.db` (gitignored)

## Prerequisites

- Node 24 or newer
- A local clone of [`FedRAMP/docs`](https://github.com/FedRAMP/docs) — by default
  expected at `../docs/` relative to this tracker. Override via `FRMR_PATH`.

```sh
# from /Users/kenith.philip/FedRAMP 20x
git clone https://github.com/FedRAMP/docs.git    # if you haven't already
cd tracker
```

## Install

```sh
npm install
```

## Ingest the FRMR data

```sh
npm run ingest
```

This reads `../docs/FRMR.documentation.json`, creates `data/tracker.db` if
needed, and (re)populates the FRMR-derived tables. Your `item_state`,
`audit_log`, `users`, and `sessions` tables are **not** touched, so re-ingest
when upstream publishes a new FRMR version and your team's progress is
preserved (state is keyed by stable FRMR IDs).

To point at a different FRMR file:

```sh
FRMR_PATH=/path/to/FRMR.documentation.json npm run ingest
```

## Run (development)

Two processes, hot-reload on both sides:

```sh
npm run dev
```

This starts:

- API at `http://localhost:4000`
- Vite dev server (with API proxy) at `http://localhost:5173`

Open `http://localhost:5173`. The first time you visit, the app detects no
users exist and prompts you to **create the first admin account**. After
that, only admins can add additional users (from the API; a future UI
can wrap this if you want).

## Run (production / single port)

```sh
npm run build       # bundles client/ into client/dist/
npm run start       # serves API + bundled client on PORT (default 4000)
```

Visit `http://localhost:4000`.

## Daily workflow

1. **Find a starting point** — Dashboard or *Gap analysis* page. The
   `next_up` list on the dashboard surfaces MUST-keyword 20x requirements
   that haven't been started yet.
2. **Open an item** — click its ID to land on the detail page. The
   statement is annotated with FRD term tooltips. Fill in:
   - **Status** — `not_started` / `in_progress` / `met` / `not_applicable` / `blocked`
   - **Owner** — pick a user (for accountability), and/or a free-text owner (for teams)
   - **Evidence URL** — link to the artifact that proves implementation
     (runbook, policy doc, security-tools dashboard, …)
   - **Last reviewed** — when an item was last validated against current state
   - **Notes** — implementation decisions, blockers, links to design docs
3. **Trace coverage** — the *NIST crosswalk* page tells you which legacy
   controls each KSI maps to. Useful for telling auditors "we already have
   evidence for ac-2.2 via KSI-IAM-AAM" — and for finding controls you
   *aren't* covering via 20x and need to address separately.
4. **Report out** — *Export* page produces CSV (good for spreadsheets) or
   JSON (good for piping into other GRC tooling).

## Updating to a newer FRMR release

```sh
cd ../docs && git pull && cd -
npm run ingest
```

Your tracker state survives. New requirements or KSIs appear as
`not_started`. If upstream removes an item, the row in `requirements` /
`indicators` is removed and any state you had for that ID becomes
orphaned (still in `item_state` — surface via SQL if you need to audit).

## Adding more users

Today, additional users are added via API (admin session required):

```sh
curl -X POST -H 'content-type: application/json' \
  -b cookies.txt \
  -d '{"email":"alice@example.com","name":"Alice","password":"strongpw1"}' \
  http://localhost:4000/api/auth/signup
```

(Get an admin session cookie via `/api/auth/login` first, or use the
browser session: open DevTools → Application → Cookies → copy `fr20x_sid`.)

## Backups

`data/tracker.db` is the entire state. For a hot, scriptable backup use
`server/backup.ts` (online `.backup()` → gzip, WAL checkpointed first):

```bash
npm run backup            # writes backups/tracker-<UTC>.db.gz
```

Restore stops at nothing-destructive-by-default: it validates the SQLite magic
header before overwriting, writes atomically (temp + rename), refuses symlink
targets, and clears stale `-wal`/`-shm` sidecars. **Stop the server first**, then
restore from a `*.db.gz`.

## Configuration (environment variables)

| Variable | Default | Purpose |
|---|---|---|
| `PORT` | `4000` | HTTP port. |
| `DB_PATH` | `data/tracker.db` | SQLite path. Open failures produce an actionable error (missing dir / not writable). |
| `TRACKER_DB_BUSY_TIMEOUT_MS` | `5000` | SQLite `busy_timeout` — concurrent writers retry internally before `SQLITE_BUSY`. |
| `TRACKER_MAX_ATTACHMENT_MB` | `25` | Per-file attachment cap (validated at startup). |
| `TRACKER_ATTACHMENT_MIME_ALLOWLIST` | common doc/image types | Comma-separated upload MIME allowlist. |
| `TRACKER_ATTACHMENTS_DIR` | `data/attachments` | Content-addressed blob store root. |
| `RL_LOGIN_PER_MIN` / `RL_LOGIN_PER_HOUR` | `5` / `30` | Login rate limits (per client IP; falls back to the TCP peer address with no proxy). |
| `RL_TOKEN_CREATE_PER_HOUR` | `10` | API-token creation rate limit. |
| `RL_API_TOKEN_PER_MIN` | `60` | Per-API-token request rate limit. |
| `NODE_ENV` | — | Set to `production` to mark cookies `Secure`. |

## Layout

```
tracker/
  server/
    index.ts          # Hono app entry
    db.ts             # SQLite open + schema init
    schema.sql        # DDL
    auth.ts           # scrypt password hashing + session helpers + middleware
    ingest.ts         # FRMR JSON → SQLite (idempotent)
    routes/
      auth.ts         # /api/auth/*
      items.ts        # /api/processes, /requirements, /indicators, /items/:type/:id (PATCH), /definitions, /users, /meta
      dashboard.ts    # /api/dashboard, /api/crosswalk
      export.ts       # /api/export?format=csv|json
  client/
    index.html
    vite.config.ts
    src/
      main.tsx, App.tsx, styles.css
      lib/api.ts, lib/auth.tsx, lib/formatting.tsx
      pages/Dashboard.tsx, GapAnalysis.tsx, Requirements.tsx, Indicators.tsx,
            ItemDetail.tsx, Crosswalk.tsx, Definitions.tsx, Export.tsx, Login.tsx
  data/               # tracker.db lives here (gitignored)
  .env.example
  package.json, tsconfig.json
```

## Security notes (local-team deployment)

- Passwords are stored with `scrypt(N=16384, r=8, p=1)` and a per-user salt.
- Session tokens are 256-bit random, hashed before storage; cookies are
  `HttpOnly` + `SameSite=Strict` + `Secure` in production.
- CSRF: `SameSite=Strict` blocks cross-origin browser-initiated requests.
  If you put this behind a tunnel or expose it on the network, add a
  reverse-proxy with TLS and consider explicit CSRF tokens.
- Every state mutation is recorded in `audit_log` with the acting user,
  field, old value, new value, and timestamp.

## What's intentionally not in v0.1

- Evidence file uploads (we link out instead — keep evidence in your
  document store)
- Multi-tenant / per-org partitioning (one tracker, one team)
- PDF reports — use the CSV export and your reporting tool of choice
- A UI for admin user management — the API is enough for now
