const { useState, useEffect, useCallback } = React;

const API_BASE = "http://localhost:8000";

// ─── Helpers ────────────────────────────────────────────────────────────────

function fmtTs(ts) {
  if (!ts) return "—";
  try {
    const d = new Date(ts);
    return d.toLocaleString("en-GB", {
      day: "2-digit", month: "short", year: "numeric",
      hour: "2-digit", minute: "2-digit", second: "2-digit",
    });
  } catch { return ts; }
}

function ConfidenceBar({ pct, showText = false }) {
  const p = Math.max(0, Math.min(100, isNaN(pct) ? 0 : pct));
  const color =
    p >= 80 ? "var(--sev-critical)" :
    p >= 60 ? "var(--sev-high)" :
    p >= 40 ? "var(--sev-medium)" : "var(--sev-low)";
  return (
    <div className="score-bar-wrap">
      <div className="score-bar-bg" style={{ width: showText ? '100%' : '60px' }}>
        <div className="score-bar-fill" style={{ width: p + "%", background: color }} />
      </div>
      <span className="score-text" style={{ color }}>{p.toFixed(1)}%</span>
    </div>
  );
}

function SeverityBadge({ severity }) {
  return <span className={`badge ${severity}`}>{severity}</span>;
}

// ─── SVG Trend Chart ─────────────────────────────────────────────────────────

function SeverityChart({ counts }) {
  if (!counts) return null;
  const max = Math.max(...Object.values(counts), 1);
  const items = [
    { label: "Critical", count: counts.Critical || 0, color: "var(--sev-critical)" },
    { label: "High", count: counts.High || 0, color: "var(--sev-high)" },
    { label: "Medium", count: counts.Medium || 0, color: "var(--sev-medium)" },
    { label: "Low", count: counts.Low || 0, color: "var(--sev-low)" }
  ];
  return (
    <div className="table-wrapper animate-fade-in" style={{ padding: '20px', marginBottom: '28px' }}>
      <h3 style={{ fontSize: '13px', marginBottom: '16px', color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.8px' }}>Alerts by Severity</h3>
      <svg width="100%" height="120" viewBox="0 0 1000 120" preserveAspectRatio="none">
        {items.map((item, idx) => {
          const barWidth = (item.count / max) * 800;
          const y = idx * 30;
          return (
            <g key={item.label} transform={`translate(0, ${y})`}>
              <text x="0" y="16" fill="var(--text-muted)" fontSize="12" fontFamily="Inter">{item.label}</text>
              <rect x="80" y="4" width={Math.max(barWidth, 2)} height="16" fill={item.color} rx="2" />
              <text x={80 + barWidth + 10} y="16" fill="var(--text-secondary)" fontSize="12" fontFamily="JetBrains Mono">{item.count}</text>
            </g>
          );
        })}
      </svg>
    </div>
  );
}

// ─── Stats Bar ───────────────────────────────────────────────────────────────

function StatsBar({ stats, alertCount }) {
  const s = stats || {};
  return (
    <div className="stats-bar animate-fade-in">
      <div className="stat-card">
        <div className="stat-label">Logs Processed</div>
        <div className="stat-value primary">{(s.total_logs_processed ?? 0).toLocaleString()}</div>
      </div>
      <div className="stat-card">
        <div className="stat-label">Total Alerts</div>
        <div className="stat-value primary">{(s.total_alerts ?? alertCount).toLocaleString()}</div>
      </div>
      <div className="stat-card">
        <div className="stat-label">Critical</div>
        <div className="stat-value critical">{s.severity_counts?.Critical ?? 0}</div>
      </div>
      <div className="stat-card">
        <div className="stat-label">High</div>
        <div className="stat-value high">{s.severity_counts?.High ?? 0}</div>
      </div>
      <div className="stat-card">
        <div className="stat-label">Medium</div>
        <div className="stat-value medium">{s.severity_counts?.Medium ?? 0}</div>
      </div>
      <div className="stat-card">
        <div className="stat-label">Low</div>
        <div className="stat-value low">{s.severity_counts?.Low ?? 0}</div>
      </div>
    </div>
  );
}

// ─── Alert Table ─────────────────────────────────────────────────────────────

function AlertRow({ a, index }) {
  const [expanded, setExpanded] = useState(false);
  const rowClass = index % 2 === 0 ? "row-even" : "row-odd";
  return (
    <>
      <tr className={`alert-row ${rowClass}`} style={{ animationDelay: `${Math.min(index * 30, 300)}ms` }} onClick={() => setExpanded(!expanded)}>
        <td className="mono" style={{ whiteSpace: 'nowrap' }}>
          <span style={{ display: 'inline-block', width: '15px', color: 'var(--text-muted)' }}>{expanded ? '▼' : '▶'}</span> {fmtTs(a.timestamp)}
        </td>
        <td className="primary">{a.user ?? "—"}</td>
        <td className="mono">{a.source_ip ?? "—"}</td>
        <td className="mono">{a.action ?? "—"}</td>
        <td><SeverityBadge severity={a.severity ?? "Medium"} /></td>
        <td><ConfidenceBar pct={a.confidence_percentage ?? 0} /></td>
        <td>
          <div className="explanation" style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', maxWidth: '180px' }}>
            {a.explanation ?? "N/A"}
          </div>
        </td>
      </tr>
      {expanded && (
        <tr className="details-row animate-fade-in">
          <td colSpan="7" className="details-td">
            <div style={{ display: 'flex', gap: '30px', flexWrap: 'wrap' }}>
               <div style={{ flex: '1 1 400px' }}>
                 <h4 style={{ color: 'var(--text-muted)', marginBottom: '8px', fontSize: '11px', textTransform: 'uppercase', letterSpacing: '0.8px' }}>Log Payload</h4>
                 <pre style={{ background: 'rgba(0,0,0,0.5)', padding: '16px', borderRadius: '8px', fontSize: '12px', overflowX: 'auto', color: 'var(--text-primary)', border: '1px solid var(--border)', fontFamily: 'JetBrains Mono, monospace' }}>
                   {JSON.stringify(a, null, 2)}
                 </pre>
               </div>
               <div style={{ flex: '1 1 400px' }}>
                 <h4 style={{ color: 'var(--text-muted)', marginBottom: '8px', fontSize: '11px', textTransform: 'uppercase', letterSpacing: '0.8px' }}>AI Threat Analysis</h4>
                 <p style={{ fontSize: '13px', lineHeight: 1.6, color: 'var(--text-primary)', marginBottom: '20px' }}>{a.explanation}</p>
                 <h4 style={{ color: 'var(--text-muted)', marginBottom: '8px', fontSize: '11px', textTransform: 'uppercase', letterSpacing: '0.8px' }}>Remediation Strategy</h4>
                 <p style={{ fontSize: '13px', color: '#ef4444', background: 'rgba(220, 38, 38, 0.1)', padding: '12px', borderRadius: '8px', border: '1px solid rgba(220, 38, 38, 0.2)' }}>⚡ {a.recommendation}</p>
                 <div style={{ marginTop: '24px' }}>
                     <h4 style={{ color: 'var(--text-muted)', marginBottom: '8px', fontSize: '11px', textTransform: 'uppercase', letterSpacing: '0.8px' }}>Anomaly Confidence Profile</h4>
                     <ConfidenceBar pct={a.confidence_percentage ?? 0} showText={true} />
                 </div>
               </div>
            </div>
          </td>
        </tr>
      )}
    </>
  );
}

function AlertTable({ alerts }) {
  if (!alerts.length) {
    return (
      <div className="table-wrapper">
        <div className="empty-state">
          <div className="icon">🛡️</div>
          <h3>No Alerts Match Criteria</h3>
          <p>Try modifying your search or click <strong>Run Ingestion</strong> to generate fresh threat alerts.</p>
        </div>
      </div>
    );
  }

  return (
    <div className="table-wrapper">
      <div className="table-scroll">
        <table>
          <thead>
            <tr>
              <th>Timestamp</th>
              <th>User</th>
              <th>Source IP</th>
              <th>Action</th>
              <th>Severity</th>
              <th>Confidence</th>
              <th>AI Analysis Overview</th>
            </tr>
          </thead>
          <tbody>
            {alerts.map((a, i) => (
              <AlertRow key={a.run_id ? `${a.run_id}-${i}` : i} a={a} index={i} />
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// ─── App Root ────────────────────────────────────────────────────────────────

function App() {
  const [alerts,    setAlerts]    = useState([]);
  const [stats,     setStats]     = useState(null);
  const [loading,   setLoading]   = useState(false);
  const [ingesting, setIngesting] = useState(false);
  const [error,     setError]     = useState(null);
  const [filter,    setFilter]    = useState("All");
  const [search,    setSearch]    = useState("");
  const [lastRefresh, setLastRefresh] = useState(null);
  const [countdown, setCountdown] = useState(30);
  const [toast,     setToast]     = useState(null);

  const fetchAlerts = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [aRes, sRes] = await Promise.all([
        fetch(`${API_BASE}/alerts?page=1&limit=100`),
        fetch(`${API_BASE}/stats`),
      ]);
      if (!aRes.ok) throw new Error(`/alerts returned ${aRes.status}`);
      const aData = await aRes.json();
      const sData = sRes.ok ? await sRes.json() : null;
      setAlerts(aData.alerts ?? []);
      setStats(sData);
      setLastRefresh(new Date());
      setCountdown(30);
    } catch (e) {
      setError(e.message || "Cannot reach API — is the FastAPI server running on port 8000?");
    } finally {
      setLoading(false);
    }
  }, []);

  const runIngest = useCallback(async () => {
    setIngesting(true);
    setError(null);
    try {
      const res = await fetch(`${API_BASE}/ingest`, { method: "POST" });
      if (!res.ok) throw new Error(`/ingest returned ${res.status}`);
      const data = await res.json();
      setToast(`Ingestion Complete: ${data.alerts_raised} anomalous threats were captured out of ${data.logs_processed} logs.`);
      setTimeout(() => setToast(null), 5000);
      await fetchAlerts();
    } catch (e) {
      setError(e.message || "Ingestion failed.");
    } finally {
      setIngesting(false);
    }
  }, [fetchAlerts]);

  const handleExportCSV = () => {
    const headers = ["Timestamp", "User", "Source IP", "Action", "Severity", "Confidence Percentage", "Analysis Recommendation"];
    const rows = filtered.map(a => [
      fmtTs(a.timestamp),
      a.user || "",
      a.source_ip || "",
      a.action || "",
      a.severity || "",
      (a.confidence_percentage ?? 0).toFixed(2),
      a.recommendation || ""
    ]);
    const csvContent = "data:text/csv;charset=utf-8," 
      + [headers.join(","), ...rows.map(e => e.map(s => `"${String(s).replace(/"/g, '""')}"`).join(","))].join("\\n");
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement("a");
    link.setAttribute("href", encodedUri);
    link.setAttribute("download", "cloud_ids_alerts.csv");
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  // Initial load
  useEffect(() => { fetchAlerts(); }, [fetchAlerts]);

  // Tick countdown timer
  useEffect(() => {
    const timer = setInterval(() => {
      setCountdown(c => {
        if (c <= 1) {
          fetchAlerts();
          return 30; // Will be reset by fetchAlerts anyway
        }
        return c - 1;
      });
    }, 1000);
    return () => clearInterval(timer);
  }, [fetchAlerts]);

  const SEVERITIES = ["All", "Critical", "High", "Medium", "Low"];
  const filtered = alerts.filter(a => {
    if (filter !== "All" && a.severity !== filter) return false;
    if (search) {
      const q = search.toLowerCase();
      const user = (a.user || "").toLowerCase();
      const ip = (a.source_ip || "").toLowerCase();
      const action = (a.action || "").toLowerCase();
      if (!user.includes(q) && !ip.includes(q) && !action.includes(q)) return false;
    }
    return true;
  });

  return (
    <>
      <header className="header">
        <div className="header-inner">
          <div className="logo">
            <div className="logo-icon">🛡</div>
            <div className="logo-text">CloudIDS</div>
          </div>
          <div className="header-status">
            <div className="live-indicator">
              <div className="live-indicator-dot" /> LIVE
            </div>
            <span>Next refresh in {countdown}s</span>
          </div>
        </div>
      </header>

      <main className="main">
        <SeverityChart counts={stats?.severity_counts} />
        <StatsBar stats={stats} alertCount={alerts.length} />

        {error && (
          <div className="error-banner">
            ⚠️ {error}
          </div>
        )}

        <div className="controls">
          <div className="controls-left">
            <div className="section-title">Live Alert Feed</div>
            {filtered.length > 0 && (
              <span className="alert-count">{filtered.length}</span>
            )}
            <input 
              type="text" 
              className="search-input" 
              placeholder="Search IP, User, Action..." 
              value={search} 
              onChange={e => setSearch(e.target.value)} 
            />
          </div>
          <div style={{ display: "flex", gap: "10px", flexWrap: "wrap", alignItems: "center" }}>
            <div className="filter-pills">
              {SEVERITIES.map(s => (
                <button
                  key={s}
                  className={`pill ${s.toLowerCase()} ${filter === s ? "active" : ""}`}
                  onClick={() => setFilter(s)}
                  id={`filter-${s.toLowerCase()}`}
                >
                  {s}
                </button>
              ))}
            </div>
            
            {/* Export CSV - Changed to btn-outline */}
            <button className="btn btn-outline" onClick={handleExportCSV}>
              📥 Export CSV
            </button>
            
            {/* Refresh */}
            <button
              id="btn-refresh"
              className="btn btn-secondary"
              onClick={fetchAlerts}
              disabled={loading || ingesting}
            >
              {loading ? <span className="spinner" /> : "↻"}
            </button>
            
            {/* Ingest */}
            <button
              id="btn-ingest"
              className="btn btn-primary"
              onClick={runIngest}
              disabled={ingesting || loading}
            >
              {ingesting ? <span className="spinner" /> : "⚡"} Run Ingestion
            </button>
          </div>
        </div>

        <AlertTable alerts={filtered} />

        <div className="footer">
          AI-Enhanced Cloud IDS · Portfolio Ready Build · Security Operations Dashboard
        </div>

        {toast && (
          <div className="toast">
            <span className="toast-icon">✅</span> {toast}
          </div>
        )}
      </main>
    </>
  );
}

ReactDOM.createRoot(document.getElementById("root")).render(<App />);
