import { useCallback, useEffect, useMemo, useState } from "react";
import { api } from "./api";

const initialEvent = {
  timestamp: Math.floor(Date.now() / 1000),
  event_type: "announcement",
  prefix: "203.0.113.0/24",
  as_path: "64510 64500",
  origin_as: "64500",
};

function formatTime(value) {
  if (!value) return "—";
  return new Date(Number(value) * 1000).toLocaleString();
}

function statusClass(value) {
  return String(value || "").toLowerCase().replaceAll("_", "-");
}

function formatScore(value) {
  return typeof value === "number" ? `${Math.round(value * 100)}%` : "Unavailable";
}

function Metric({ label, value, tone = "" }) {
  return (
    <div className={`metric ${tone}`}>
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function Finding({ finding }) {
  const rule = finding.rule || "RPKI_VALIDATION";
  const state = finding.status || finding.state || "INFO";
  return (
    <article className={`finding ${statusClass(state)}`}>
      <div className="finding-heading">
        <strong>{rule}</strong>
        <span className={`pill ${statusClass(state)}`}>{state}</span>
      </div>
      <p>{finding.reason || finding.findings?.join(" ") || "No additional evidence."}</p>
      <div className="finding-meta">
        {finding.observed_origin && <span>Observed AS{finding.observed_origin}</span>}
        {finding.covering_prefix && <span>Covering {finding.covering_prefix}</span>}
        {finding.expected_origins && (
          <span>Expected AS{finding.expected_origins.join(", AS")}</span>
        )}
      </div>
    </article>
  );
}

function App() {
  const [event, setEvent] = useState(initialEvent);
  const [result, setResult] = useState(null);
  const [routes, setRoutes] = useState([]);
  const [history, setHistory] = useState([]);
  const [health, setHealth] = useState("checking");
  const [model, setModel] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const refresh = useCallback(async () => {
    try {
      const [healthResult, routeResult, historyResult, modelResult] =
        await Promise.all([
          api.health(),
          api.routes(),
          api.history(),
          api.modelStatus(),
        ]);
      setHealth(healthResult.status);
      setRoutes(routeResult);
      setHistory(historyResult);
      setModel(modelResult);
    } catch (requestError) {
      setHealth("offline");
      setError(requestError.message);
    }
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  const suspiciousCount = useMemo(
    () => history.filter((item) => item.result?.suspicious).length,
    [history],
  );

  const updateEvent = (field, value) => {
    setEvent((current) => ({ ...current, [field]: value }));
  };

  const submit = async (formEvent) => {
    formEvent.preventDefault();
    setLoading(true);
    setError("");
    try {
      const payload = {
        ...event,
        timestamp: Number(event.timestamp),
        origin_as: event.event_type === "withdrawal" ? undefined : Number(event.origin_as),
        as_path:
          event.event_type === "withdrawal"
            ? []
            : event.as_path.split(/[\s,]+/).filter(Boolean).map(Number),
      };
      setResult(await api.detect(payload));
      await refresh();
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="app-shell">
      <header className="topbar">
        <div className="brand">
          <div className="brand-mark">B</div>
          <div>
            <p className="eyebrow">NETWORK SECURITY / PS-005</p>
            <h1>BGP Anomaly Monitor</h1>
          </div>
        </div>
        <div className="system-status">
          <span className={`status-dot ${health === "ok" ? "online" : ""}`} />
          API {health}
          <span className="api-url">{api.baseUrl}</span>
        </div>
      </header>

      <main className="content">
        <section className="hero">
          <div>
            <p className="eyebrow">EXPLAINABLE ROUTE INTELLIGENCE</p>
            <h2>See every signal behind a routing alert.</h2>
            <p className="hero-copy">
              Test announcements and withdrawals against origin inventory,
              RPKI authorization, and more-specific prefix rules.
            </p>
          </div>
          <div className="hero-badge">
            <span className="pulse" />
            Detection engine ready
          </div>
        </section>

        <section className="metrics-grid">
          <Metric label="Active routes" value={routes.length} />
          <Metric label="Events recorded" value={history.length} />
          <Metric label="Suspicious events" value={suspiciousCount} tone="warning" />
          <Metric
            label="ML model"
            value={model?.available ? "Ready" : "Not loaded"}
            tone={model?.available ? "success" : ""}
          />
        </section>

        <div className="workspace-grid">
          <section className="panel detection-panel">
            <div className="panel-heading">
              <div>
                <p className="eyebrow">LIVE TEST CONSOLE</p>
                <h3>Evaluate a BGP event</h3>
              </div>
              <span className="panel-tag">POST /detect</span>
            </div>
            <form onSubmit={submit}>
              <div className="field-row">
                <label>
                  Event type
                  <select
                    value={event.event_type}
                    onChange={(e) => updateEvent("event_type", e.target.value)}
                  >
                    <option value="announcement">Announcement</option>
                    <option value="withdrawal">Withdrawal</option>
                  </select>
                </label>
                <label>
                  Timestamp
                  <input
                    type="number"
                    value={event.timestamp}
                    onChange={(e) => updateEvent("timestamp", e.target.value)}
                  />
                </label>
              </div>
              <label>
                Prefix
                <input
                  value={event.prefix}
                  onChange={(e) => updateEvent("prefix", e.target.value)}
                  placeholder="203.0.113.0/24"
                />
              </label>
              {event.event_type === "announcement" && (
                <>
                  <div className="field-row">
                    <label>
                      Origin ASN
                      <input
                        value={event.origin_as}
                        onChange={(e) => updateEvent("origin_as", e.target.value)}
                        placeholder="64500"
                      />
                    </label>
                    <label>
                      AS_PATH
                      <input
                        value={event.as_path}
                        onChange={(e) => updateEvent("as_path", e.target.value)}
                        placeholder="64510 64500"
                      />
                    </label>
                  </div>
                  <p className="field-help">
                    The backend independently calculates RPKI state from loaded ROAs.
                  </p>
                </>
              )}
              <button className="primary-button" disabled={loading}>
                {loading ? "Evaluating..." : "Run detection"}
                <span>→</span>
              </button>
            </form>
            {error && <div className="error-box">{error}</div>}
          </section>

          <section className="panel result-panel">
            <div className="panel-heading">
              <div>
                <p className="eyebrow">CONSOLIDATED ASSESSMENT</p>
                <h3>Detection result</h3>
              </div>
              {result && (
                <span className={`pill ${result.suspicious ? "alert" : "pass"}`}>
                  {result.suspicious ? "SUSPICIOUS" : "CLEAR"}
                </span>
              )}
            </div>
            {!result ? (
              <div className="empty-state">
                <div className="empty-icon">◎</div>
                <strong>Awaiting an event</strong>
                <p>Submit an announcement to see rule-by-rule evidence here.</p>
              </div>
            ) : (
              <>
                <div className="result-summary">
                  <div>
                    <span className="muted">Prefix</span>
                    <strong>{result.prefix}</strong>
                  </div>
                  <div>
                    <span className="muted">Severity</span>
                    <strong className={statusClass(result.severity)}>{result.severity}</strong>
                  </div>
                  <div>
                    <span className="muted">RPKI</span>
                    <strong>{result.rpki_state}</strong>
                  </div>
                  <div>
                    <span className="muted">ML score</span>
                    <strong className={result.ml_score == null ? "muted" : ""}>
                      {formatScore(result.ml_score)}
                    </strong>
                  </div>
                </div>
                <p className="result-reason">{result.reason}</p>
                <div className="findings-list">
                  {result.findings.map((finding, index) => (
                    <Finding finding={finding} key={`${finding.rule || finding.state}-${index}`} />
                  ))}
                </div>
                <div className="recommendation">
                  <span>RECOMMENDED ACTION</span>
                  <p>{result.recommended_action}</p>
                </div>
              </>
            )}
          </section>
        </div>

        <div className="lower-grid">
          <section className="panel">
            <div className="panel-heading">
              <div>
                <p className="eyebrow">ROUTING STATE</p>
                <h3>Active routes</h3>
              </div>
              <button className="text-button" onClick={refresh}>Refresh ↻</button>
            </div>
            <div className="table-wrap">
              <table>
                <thead><tr><th>Prefix</th><th>Origin</th><th>Updated</th></tr></thead>
                <tbody>
                  {routes.length === 0 ? (
                    <tr><td colSpan="3" className="table-empty">No active routes</td></tr>
                  ) : routes.map((route) => (
                    <tr key={route.prefix}>
                      <td className="mono">{route.prefix}</td>
                      <td>AS{route.origin_as}</td>
                      <td className="muted">{formatTime(route.timestamp)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>

          <section className="panel">
            <div className="panel-heading">
              <div>
                <p className="eyebrow">EVENT HISTORY</p>
                <h3>Recent activity</h3>
              </div>
            </div>
            <div className="activity-list">
              {history.length === 0 ? (
                <div className="table-empty">No events recorded</div>
              ) : history.slice(0, 6).map((item) => (
                <div className="activity-item" key={item.id}>
                  <span className={`activity-icon ${item.event_type === "withdrawal" ? "withdrawal" : ""}`}>
                    {item.event_type === "withdrawal" ? "−" : "↑"}
                  </span>
                  <div>
                    <strong>{item.event_type} <span className="mono">{item.prefix}</span></strong>
                    <span className="muted">{formatTime(item.timestamp)}</span>
                  </div>
                  <span className={`pill ${statusClass(item.action)}`}>{item.action}</span>
                </div>
              ))}
            </div>
          </section>
        </div>
      </main>
      <footer>
        <span>Rule-based detection is authoritative for RPKI validation.</span>
        <span>Frontend build 0.1.0</span>
      </footer>
    </div>
  );
}

export default App;
