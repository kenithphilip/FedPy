export function Export() {
  return (
    <div>
      <h1 className="h1">Export</h1>
      <p className="muted">Download your full tracker state (FRMR identifiers + statuses + notes + evidence + owners).</p>
      <div className="card">
        <p>Two formats are supported:</p>
        <ul>
          <li><strong>CSV</strong> — one row per requirement and indicator. Good for spreadsheets and external GRC ingest.</li>
          <li><strong>JSON</strong> — same content, structured.</li>
        </ul>
        <div className="row" style={{ marginTop: 12, gap: 10 }}>
          <a href="/api/export?format=csv" download><button>Download CSV</button></a>
          <a href="/api/export?format=json" download><button className="secondary">Download JSON</button></a>
        </div>
      </div>
    </div>
  );
}
