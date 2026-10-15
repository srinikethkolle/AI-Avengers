import { useEffect, useState } from "react";
import {
  ShieldCheck,
  LayoutDashboard,
  Bot,
  Activity,
  ClipboardCheck,
  Settings,
  RefreshCw,
  ShieldAlert,
  CheckCircle2,
  XCircle,
  Clock3,
  Play,
  RotateCcw,
  Sliders,
  PlusCircle,
  AlertTriangle,
  Lock,
  UserCheck,
  ShieldX,
  MessageSquare,
  Send,
  Sparkles,
  BarChart3,
  CreditCard,
  X,
} from "lucide-react";
import "./App.css";
import QuarantineModal from "./components/QuarantineModal";

const API = (
  import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8000"
).replace(/\/$/, "");

const menu = [
  { label: "Overview", icon: LayoutDashboard },
  { label: "Secured AI Chatbot", icon: MessageSquare },
  { label: "Agents", icon: Bot },
  { label: "Security Events", icon: Activity },
  { label: "Approval Center", icon: ClipboardCheck },
  { label: "Policies & Sandbox", icon: Settings },
];

const emptyDashboard = {
  total_agents: 0,
  allowed_requests: 0,
  denied_requests: 0,
  pending_approvals: 0,
  quarantined_agents: 0,
};

function Badge({ children, type = "neutral" }) {
  const norm = String(children || type).toLowerCase().replace(/[\s-]/g, "_");
  let badgeClass = "badge-neutral";

  if (["allow", "approved", "low", "active"].includes(norm)) {
    badgeClass = "badge-low";
  } else if (["hold_for_approval", "pending", "medium"].includes(norm)) {
    badgeClass = "badge-medium";
  } else if (["deny", "rejected", "reject", "high", "inactive"].includes(norm)) {
    badgeClass = "badge-high";
  } else if (["quarantine", "quarantined"].includes(norm)) {
    badgeClass = "badge-quarantine";
  }

  return <span className={`badge ${badgeClass}`}>{children}</span>;
}

function Risk({ score }) {
  const value = Number(score);
  const type = value >= 70 ? "high" : value >= 40 ? "medium" : "low";

  return (
    <Badge type={type}>
      {Number.isFinite(value) ? value : "0"} / 100
    </Badge>
  );
}

function EventTable({ events, onReviewQuarantine }) {
  if (!events || !events.length) {
    return <div className="empty">No security events have been recorded.</div>;
  }

  return (
    <div className="table-scroll">
      <table>
        <thead>
          <tr>
            <th>Timestamp</th>
            <th>Agent</th>
            <th>Action</th>
            <th>Risk Score</th>
            <th>Decision</th>
            <th>Reason & Context</th>
          </tr>
        </thead>
        <tbody>
          {events.map((event) => (
            <tr key={event.id || Math.random()}>
              <td style={{ color: "var(--muted)", whiteSpace: "nowrap" }}>
                {event.timestamp || "Just now"}
              </td>
              <td>
                <strong>{event.agent_name || event.agent_id}</strong>
                {event.agent_id && (
                  <div style={{ fontSize: "10px", color: "var(--muted)" }}>{event.agent_id}</div>
                )}
              </td>
              <td><code>{event.action}</code></td>
              <td><Risk score={event.risk_score} /></td>
              <td>
                <Badge>{event.decision}</Badge>
                {event.decision === "QUARANTINE" && onReviewQuarantine && (
                  <button
                    type="button"
                    className="btn btn-secondary btn-sm"
                    style={{ padding: "2px 7px", fontSize: "10px", marginLeft: "6px" }}
                    onClick={() => onReviewQuarantine(event)}
                  >
                    Inspect
                  </button>
                )}
              </td>
              <td style={{ maxWidth: "340px" }}>{event.reason}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function ApprovalTable({ approvals, busyId, onReview }) {
  if (!approvals || !approvals.length) {
    return <div className="empty">No pending approval requests in the queue.</div>;
  }

  return (
    <div className="table-scroll">
      <table>
        <thead>
          <tr>
            <th>Agent</th>
            <th>Requested Action</th>
            <th>Risk</th>
            <th>Trigger Reason & Metadata</th>
            <th>Human Review</th>
          </tr>
        </thead>
        <tbody>
          {approvals.map((item) => (
            <tr key={item.id}>
              <td>
                <strong>{item.agent_name}</strong>
                <div style={{ fontSize: "10px", color: "var(--muted)" }}>{item.agent_id}</div>
              </td>
              <td><code>{item.action}</code></td>
              <td><Risk score={item.risk_score} /></td>
              <td>
                <div>{item.reason}</div>
                {item.metadata && Object.keys(item.metadata).length > 0 && (
                  <div style={{ marginTop: "6px" }}>
                    {Object.entries(item.metadata).map(([k, v]) => (
                      <span key={k} className="meta-chip">
                        {k}: {String(v)}
                      </span>
                    ))}
                  </div>
                )}
              </td>
              <td>
                <div className="review-actions">
                  <button
                    disabled={busyId !== null}
                    className="approve"
                    onClick={() => onReview(item.id, "approve")}
                  >
                    {busyId === item.id ? "Saving..." : "Approve Action"}
                  </button>
                  <button
                    disabled={busyId !== null}
                    className="reject"
                    onClick={() => onReview(item.id, "reject")}
                  >
                    Reject
                  </button>
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default function App() {
  const [page, setPage] = useState("Overview");
  const [dashboard, setDashboard] = useState(emptyDashboard);
  const [agents, setAgents] = useState([]);
  const [events, setEvents] = useState([]);
  const [approvals, setApprovals] = useState([]);
  const [policies, setPolicies] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [busyId, setBusyId] = useState(null);

  // Simulation State
  const [simRunning, setSimRunning] = useState(false);
  const [simResults, setSimResults] = useState(null);

  // Interactive Continuous Authorization Evaluator
  const [evalAgentId, setEvalAgentId] = useState("agent-finops-01");
  const [evalAction, setEvalAction] = useState("transfer_funds");
  const [evalMeta, setEvalMeta] = useState({
    privileged: false,
    external_source: false,
    new_device: false,
    high_impact: false,
    out_of_hours: false,
    admin_action: false,
  });
  const [evalResult, setEvalResult] = useState(null);
  const [evaluating, setEvaluating] = useState(false);

  // New Agent Form
  const [showAddAgent, setShowAddAgent] = useState(false);
  const [newAgent, setNewAgent] = useState({
    agent_id: "",
    name: "",
    role: "",
    permissions: "read_report, list_users",
    prohibited: "delete_user",
  });

  // Thresholds state
  const [thresholds, setThresholds] = useState({
    risk_threshold: 60,
    quarantine_threshold: 85,
    approval_threshold: 40,
  });

  // Chatbot State
  const [chatMessages, setChatMessages] = useState([]);
  const [chatInput, setChatInput] = useState("");
  const [chatAgentId, setChatAgentId] = useState("agent-finops-01");
  const [chatContext, setChatContext] = useState({
    source: "internal",
    privileged: false,
    out_of_hours: false,
    new_device: false,
    high_impact: false,
  });
  const [chatSending, setChatSending] = useState(false);
  const [chatPresets, setChatPresets] = useState([]);
  const [chatExecPending, setChatExecPending] = useState(null);
  const [quarantineModalIncident, setQuarantineModalIncident] = useState(null);

  async function getJSON(path) {
    const response = await fetch(`${API}${path}`);
    if (!response.ok) {
      throw new Error(`${path} returned HTTP ${response.status}`);
    }
    return response.json();
  }

  async function refresh() {
    setLoading(true);
    setError("");

    try {
      const [stats, agentRows, eventRows, approvalRows, policyData] =
        await Promise.all([
          getJSON("/api/dashboard"),
          getJSON("/api/agents"),
          getJSON("/api/events"),
          getJSON("/api/approvals"),
          getJSON("/api/policies").catch(() => null),
        ]);

      setDashboard(stats);
      setAgents(agentRows);
      setEvents(eventRows);
      setApprovals(approvalRows);
      if (policyData && policyData.active_thresholds) {
        setPolicies(policyData);
        setThresholds(policyData.active_thresholds);
      }

      getJSON("/api/chat/presets").then(setChatPresets).catch(() => {});
      getJSON("/api/chat/history").then((hist) => {
        if (hist && hist.length > 0 && chatMessages.length === 0) {
          setChatMessages(hist);
        }
      }).catch(() => {});
    } catch (err) {
      setError(
        `${err.message}. Ensure the TrustGuard FastAPI backend is running on http://127.0.0.1:8000.`
      );
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    refresh();
    const timer = window.setInterval(refresh, 15000);
    return () => window.clearInterval(timer);
  }, []);

  async function review(id, decision) {
    setBusyId(id);
    setNotice("");
    setError("");

    try {
      const response = await fetch(`${API}/api/approvals/${id}/decision`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ decision }),
      });

      const result = await response.json();
      if (!response.ok) {
        throw new Error(result.detail || "Review action failed.");
      }

      setNotice(`Request #${id}: ${result.status}`);
      await refresh();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusyId(null);
    }
  }

  async function toggleQuarantine(agentId) {
    try {
      setError("");
      const response = await fetch(`${API}/api/agents/${agentId}/quarantine`, {
        method: "POST",
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail || "Toggle failed");
      setNotice(`Agent ${agentId} status updated to: ${data.new_status}`);
      await refresh();
    } catch (err) {
      setError(err.message);
    }
  }

  async function handleAddAgent(e) {
    e.preventDefault();
    if (!newAgent.agent_id || !newAgent.name) {
      setError("Please provide an Agent ID and Name.");
      return;
    }

    try {
      const perms = newAgent.permissions
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean);
      const prohib = newAgent.prohibited
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean);

      const response = await fetch(`${API}/api/agents`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          agent_id: newAgent.agent_id,
          name: newAgent.name,
          role: newAgent.role || "Autonomous Agent",
          permissions: perms,
          prohibited: prohib,
        }),
      });

      if (!response.ok) {
        const errData = await response.json();
        throw new Error(errData.detail || "Failed to register agent");
      }

      setNotice(`Successfully registered identity for agent '${newAgent.name}'`);
      setShowAddAgent(false);
      setNewAgent({
        agent_id: "",
        name: "",
        role: "",
        permissions: "read_report, list_users",
        prohibited: "delete_user",
      });
      await refresh();
    } catch (err) {
      setError(err.message);
    }
  }

  async function runSimulation() {
    setSimRunning(true);
    setNotice("Running realistic multi-stage autonomous attack & continuous authorization simulation...");
    setError("");

    try {
      const response = await fetch(`${API}/api/simulation/run`, {
        method: "POST",
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail || "Simulation failed");
      setSimResults(data.results);
      setNotice("Simulation completed! Continuous authorization successfully evaluated and contained all steps.");
      await refresh();
    } catch (err) {
      setError(err.message);
    } finally {
      setSimRunning(false);
    }
  }

  async function handleEvaluateCustom(e) {
    e.preventDefault();
    setEvaluating(true);
    setError("");
    setEvalResult(null);

    try {
      const metadata = {};
      if (evalMeta.privileged) metadata.privileged = true;
      if (evalMeta.external_source) metadata.source = "external";
      if (evalMeta.new_device) metadata.new_device = true;
      if (evalMeta.high_impact) metadata.high_impact = true;
      if (evalMeta.out_of_hours) metadata.out_of_hours = true;
      if (evalMeta.admin_action) metadata.admin_action = true;

      const response = await fetch(`${API}/api/evaluate`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          agent_id: evalAgentId,
          action: evalAction,
          metadata,
        }),
      });

      const data = await response.json();
      if (!response.ok) throw new Error(data.detail || "Evaluation failed");
      setEvalResult(data);
      await refresh();
    } catch (err) {
      setError(err.message);
    } finally {
      setEvaluating(false);
    }
  }

  async function handleUpdateThresholds(e) {
    e.preventDefault();
    try {
      setError("");
      const response = await fetch(`${API}/api/policies`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          risk_threshold: Number(thresholds.risk_threshold),
          quarantine_threshold: Number(thresholds.quarantine_threshold),
          approval_threshold: Number(thresholds.approval_threshold),
        }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail || "Failed to update policies");
      setNotice("Security policy thresholds updated successfully.");
      await refresh();
    } catch (err) {
      setError(err.message);
    }
  }

  async function resetDemo() {
    if (!window.confirm("Reset all demo data back to baseline?")) return;
    try {
      await fetch(`${API}/api/reset`, { method: "POST" });
      setSimResults(null);
      setEvalResult(null);
      setChatMessages([]);
      setNotice("Demo state successfully reset to initial baseline.");
      await refresh();
    } catch (err) {
      setError(err.message);
    }
  }

  async function handleSendChat(textToSend = null, contextOverride = null, agentIdOverride = null) {
    const message = (textToSend !== null ? textToSend : chatInput).trim();
    if (!message) return;

    const targetAgentId = agentIdOverride || chatAgentId;
    const targetContext = contextOverride || chatContext;

    setChatSending(true);
    setError("");

    const tempUserMsg = {
      id: `temp-${Date.now()}`,
      sender: "user",
      user_message: message,
      timestamp: "Just now",
    };
    setChatMessages((prev) => [...prev, tempUserMsg]);
    if (textToSend === null) setChatInput("");

    try {
      const response = await fetch(`${API}/api/chat`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          agent_id: targetAgentId,
          message: message,
          context: targetContext,
        }),
      });

      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.detail || "Failed to process message");
      }

      setChatMessages((prev) => [...prev.filter((m) => m.id !== tempUserMsg.id), data]);
      await refresh();
    } catch (err) {
      setError(`Chat Error: ${err.message}`);
    } finally {
      setChatSending(false);
    }
  }

  async function handleExecuteApproved(approvalId) {
    setChatExecPending(approvalId);
    setError("");
    try {
      const response = await fetch(`${API}/api/chat/execute-approved`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          approval_id: approvalId,
          agent_id: chatAgentId,
        }),
      });
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.detail || "Action execution failed");
      }
      setNotice(`Action for Ticket #${approvalId} executed successfully!`);
      if (data.entry) {
        setChatMessages((prev) => [...prev, data.entry]);
      }
      await refresh();
    } catch (err) {
      setError(`Execution Error: ${err.message}`);
    } finally {
      setChatExecPending(null);
    }
  }

  async function handleClearChat() {
    try {
      await fetch(`${API}/api/chat/reset`, { method: "POST" });
      setChatMessages([]);
      setNotice("Chat history cleared");
    } catch (err) {
      setError(err.message);
    }
  }

  const stats = [
    {
      label: "Registered Agents",
      value: dashboard.total_agents,
      icon: Bot,
      color: "cyan",
    },
    {
      label: "Allowed Requests",
      value: dashboard.allowed_requests,
      icon: CheckCircle2,
      color: "green",
    },
    {
      label: "Denied Requests",
      value: dashboard.denied_requests,
      icon: XCircle,
      color: "red",
    },
    {
      label: "Pending Approvals",
      value: dashboard.pending_approvals,
      icon: Clock3,
      color: "amber",
    },
    {
      label: "Quarantined Agents",
      value: dashboard.quarantined_agents,
      icon: ShieldAlert,
      color: "purple",
    },
  ];

  return (
    <>
      <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark"><ShieldCheck size={25} /></div>
          <div>
            <strong>TRUST <span>VERIFY</span></strong>
            <small>CONTINUOUS AUTHORIZATION ENGINE</small>
          </div>
        </div>

        <div className="nav-caption">WORKSPACE NAVIGATION</div>

        <nav className="nav">
          {menu.map(({ label, icon: Icon }) => (
            <button
              key={label}
              className={`nav-item ${page === label ? "selected" : ""}`}
              onClick={() => setPage(label)}
            >
              <Icon size={18} />
              <span>{label}</span>
              {label === "Approval Center" && dashboard.pending_approvals > 0 && (
                <span className="nav-number">{dashboard.pending_approvals}</span>
              )}
            </button>
          ))}
        </nav>

        <div className="sidebar-bottom">
          <div className="status-dot" />
          <span>Continuous Engine Active · v1.0.0</span>
        </div>
      </aside>

      <main className="main">
        <header className="topbar">
          <div>
            <h1>{page}</h1>
          </div>
          <div className="topbar-actions">
            <button className="btn btn-secondary" onClick={refresh} disabled={loading}>
              <RefreshCw size={15} />
              {loading ? "Syncing..." : "Refresh"}
            </button>
            <button className="btn btn-primary" onClick={runSimulation} disabled={simRunning}>
              <Play size={15} />
              {simRunning ? "Simulating..." : "Run Attack & Governance Demo"}
            </button>
            <button className="btn btn-secondary" onClick={resetDemo} title="Reset to initial state">
              <RotateCcw size={15} />
            </button>
          </div>
        </header>

        {error && (
          <div className="message error" role="alert">
            <span>{error}</span>
            <button className="link-button" onClick={() => setError("")}>Dismiss</button>
          </div>
        )}
        {notice && (
          <div className="message success" role="status">
            <span>{notice}</span>
            <button className="link-button" onClick={() => setNotice("")}>Dismiss</button>
          </div>
        )}

        {/* OVERVIEW TAB */}
        {page === "Overview" && (
          <>
            <section className="hero">
              <div>
                <h2>Stop Standing Privilege for <em>Autonomous AI Agents</em></h2>
                <p>
                  Most organizations authenticate an AI agent once and grant permanent standing privilege.
                  TrustGuard continuously re-evaluates authorization on <strong>every sensitive action</strong>,
                  calculating dynamic runtime risk and holding sensitive operations for human approval or quarantining compromised agents.
                </p>
                <div style={{ display: "flex", gap: "10px", flexWrap: "wrap" }}>
                  <button className="btn btn-primary" onClick={runSimulation} disabled={simRunning}>
                    <Play size={15} /> Run Live Multi-Stage Governance Attack Simulation
                  </button>
                  <button className="btn btn-secondary" onClick={() => setPage("Policies & Sandbox")}>
                    <Sliders size={15} /> Open Policy Simulator
                  </button>
                </div>
              </div>
              <div className="hero-icon"><ShieldCheck size={52} /></div>
            </section>

            <section className="stats-grid">
              {stats.map(({ label, value, icon: Icon, color }) => (
                <article className="stat-card" key={label}>
                  <div className="stat-top">
                    <span>{label}</span>
                    <span className={`stat-icon ${color}`}><Icon size={19} /></span>
                  </div>
                  <strong>{loading ? "—" : value ?? "—"}</strong>
                  <small>Real-time policy telemetry</small>
                </article>
              ))}
            </section>

            {/* Simulation Results Display if triggered */}
            {simResults && (
              <section className="panel">
                <div className="panel-heading">
                  <div>
                    <h2>Multi-Stage Autonomous Agent Incident Simulation Results</h2>
                    <p>Demonstrating how continuous re-evaluation prevents privilege escalation in realistic workflows</p>
                  </div>
                  <button className="link-button" onClick={() => setSimResults(null)} style={{ display: "inline-flex", alignItems: "center", gap: "5px" }}>
                    <X size={13} />
                    <span>Close Results</span>
                  </button>
                </div>
                <div className="panel-body">
                  <div className="sim-steps-container">
                    {simResults.map((step) => (
                      <div className="sim-step-card" key={step.step}>
                        <div className="sim-step-num">{step.step}</div>
                        <div className="sim-step-content">
                          <div className="sim-step-title">
                            <span>{step.title} — Agent: <code>{step.agent_id}</code> (Action: <code>{step.action}</code>)</span>
                            <Badge>{step.result.decision}</Badge>
                          </div>
                          <div className="sim-step-desc">{step.description}</div>
                          <div className="sim-step-reason">
                            <strong>Engine Reason:</strong> {step.result.reason.join(" ")}
                            <div style={{ marginTop: "4px", fontSize: "10px", color: "var(--accent)" }}>
                              Calculated Risk Score: {step.result.risk_score} / 100 · Restriction: {step.result.restriction}
                            </div>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </section>
            )}

            <section className="panel">
              <div className="panel-heading">
                <div>
                  <h2>Recent Authorization Decisions</h2>
                  <p>Immutable audit trail of per-action security evaluations</p>
                </div>
                <button className="link-button" onClick={() => setPage("Security Events")}>
                  View all events ({events.length}) →
                </button>
              </div>
              <EventTable events={events.slice(0, 5)} />
            </section>

            <section className="panel">
              <div className="panel-heading">
                <div>
                  <h2>Pending Human Approvals</h2>
                  <p>Sensitive actions held for Human-In-The-Loop review</p>
                </div>
                <button className="link-button" onClick={() => setPage("Approval Center")}>
                  Open review queue ({approvals.length}) →
                </button>
              </div>
              <ApprovalTable
                approvals={approvals.slice(0, 5)}
                busyId={busyId}
                onReview={review}
              />
            </section>
          </>
        )}

        {/* SECURED AI CHATBOT TAB */}
        {page === "Secured AI Chatbot" && (
          <section className="panel chatbot-panel" data-ui="panel">
            {/* Header: Persona Switcher and Controls */}
            <div className="chatbot-header">
              <div className="chatbot-agent-selector">
                <span className="form-label" style={{ margin: 0 }}>Active AI Persona:</span>
                <select
                  className="form-select"
                  style={{ width: "auto", minWidth: "260px" }}
                  value={chatAgentId}
                  onChange={(e) => setChatAgentId(e.target.value)}
                >
                  {agents.map((a) => (
                    <option key={a.id} value={a.id}>
                      {a.name} ({a.role}) - [{a.status}]
                    </option>
                  ))}
                </select>
                {(() => {
                  const selAgent = agents.find((a) => a.id === chatAgentId);
                  return selAgent ? <Badge>{selAgent.status}</Badge> : null;
                })()}
              </div>

              <div style={{ display: "flex", gap: "8px" }}>
                <button
                  type="button"
                  className="btn btn-secondary btn-sm"
                  onClick={handleClearChat}
                >
                  <RotateCcw size={14} /> Clear Chat
                </button>
              </div>
            </div>

            {/* Agent Capabilities Bar */}
            {(() => {
              const selAgent = agents.find((a) => a.id === chatAgentId);
              if (!selAgent) return null;
              return (
                <div className="agent-cap-bar">
                  <div className="cap-section">
                    <span className="cap-label">Explicit Permissions:</span>
                    <code className="cap-text green">{selAgent.permissions || "None"}</code>
                  </div>
                  <div className="cap-section">
                    <span className="cap-label">Mandatory Prohibitions:</span>
                    <code className="cap-text red">{selAgent.prohibited || "None"}</code>
                  </div>
                </div>
              );
            })()}

            {/* Environmental Threat Context Simulation Bar */}
            <div className="chatbot-context-bar">
              <div className="context-title">
                <ShieldAlert size={14} style={{ color: "var(--accent)" }} />
                <span>Simulate Environmental Threat Indicators:</span>
              </div>
              <div className="context-options">
                <label className="checkbox-item-sm">
                  <input
                    type="checkbox"
                    checked={chatContext.source === "external" || chatContext.source === "untrusted"}
                    onChange={(e) =>
                      setChatContext({
                        ...chatContext,
                        source: e.target.checked ? "external" : "internal",
                      })
                    }
                  />
                  Untrusted / External Source (+15)
                </label>
                <label className="checkbox-item-sm">
                  <input
                    type="checkbox"
                    checked={chatContext.privileged}
                    onChange={(e) =>
                      setChatContext({
                        ...chatContext,
                        privileged: e.target.checked,
                      })
                    }
                  />
                  Privileged Execution (+20)
                </label>
                <label className="checkbox-item-sm">
                  <input
                    type="checkbox"
                    checked={chatContext.out_of_hours}
                    onChange={(e) =>
                      setChatContext({
                        ...chatContext,
                        out_of_hours: e.target.checked,
                      })
                    }
                  />
                  Out-of-Hours (+10)
                </label>
                <label className="checkbox-item-sm">
                  <input
                    type="checkbox"
                    checked={chatContext.new_device}
                    onChange={(e) =>
                      setChatContext({
                        ...chatContext,
                        new_device: e.target.checked,
                      })
                    }
                  />
                  New / Abnormal Device (+15)
                </label>
                <label className="checkbox-item-sm">
                  <input
                    type="checkbox"
                    checked={chatContext.high_impact}
                    onChange={(e) =>
                      setChatContext({
                        ...chatContext,
                        high_impact: e.target.checked,
                      })
                    }
                  />
                  High Impact Batch (+20)
                </label>
              </div>
            </div>

            {/* Quick Test Presets (One-Click Scenario Testing) */}
            <div className="chatbot-presets-drawer">
              <div className="presets-header">
                <Sparkles size={14} style={{ color: "var(--warning)" }} />
                <span>One-Click Test Scenarios (Evaluate TrustGuard Security Features):</span>
              </div>
              <div className="presets-chips">
                {chatPresets.map((p) => {
                  let catClass = "chip-allow";
                  if (p.expected_decision === "HOLD_FOR_APPROVAL") catClass = "chip-hold";
                  if (p.expected_decision === "DENY") catClass = "chip-deny";
                  if (p.expected_decision === "QUARANTINE") catClass = "chip-quarantine";

                  return (
                    <button
                      key={p.id}
                      type="button"
                      className={`preset-chip ${catClass}`}
                      onClick={() => {
                        setChatAgentId(p.agent_id);
                        setChatContext(p.context);
                        handleSendChat(p.prompt, p.context, p.agent_id);
                      }}
                      title={p.description}
                    >
                      <span className="preset-expected">[{p.expected_decision}]</span>
                      <strong>{p.title}</strong>
                    </button>
                  );
                })}
              </div>
            </div>

            {/* Chat Conversation Stream */}
            <div className="chatbot-messages">
              {chatMessages.length === 0 ? (
                <div className="chat-empty-state">
                  <div className="empty-icon"><Bot size={36} /></div>
                  <h3>TrustGuard Secured AI Agent Chatbot</h3>
                  <p>
                    This AI chatbot continuously enforces zero-standing-privilege authorization.
                    Every single sensitive action is re-evaluated dynamically before tool execution.
                  </p>
                  <div className="quick-suggestions">
                    <button
                      type="button"
                      className="quick-btn"
                      onClick={() => handleSendChat("Show me the quarterly financial summary report")}
                    >
                      <BarChart3 size={14} /> "Show me the quarterly financial summary report" (Low Risk · ALLOW)
                    </button>
                    <button
                      type="button"
                      className="quick-btn"
                      onClick={() => handleSendChat("Transfer $5,000 to vendor Acme Corp")}
                    >
                      <CreditCard size={14} /> "Transfer $5,000 to vendor Acme Corp" (Sensitive · HOLD FOR APPROVAL)
                    </button>
                    <button
                      type="button"
                      className="quick-btn"
                      onClick={() => handleSendChat("Delete user account bob from identity database")}
                    >
                      <ShieldAlert size={14} /> "Delete user account bob" (Mandatory Security Rule · DENY)
                    </button>
                  </div>
                </div>
              ) : (
                chatMessages.map((msg, idx) => (
                  <div key={msg.id || idx} className="chat-turn">
                    {/* User Bubble */}
                    {msg.user_message && (
                      <div className="chat-bubble user-bubble">
                        <div className="bubble-header">
                          <strong>You</strong>
                          <span className="timestamp">{msg.timestamp || "Just now"}</span>
                        </div>
                        <div className="bubble-content">{msg.user_message}</div>
                      </div>
                    )}

                    {/* Agent Bubble */}
                    <div className="chat-bubble agent-bubble">
                      <div className="bubble-header">
                        <strong>{msg.agent_name || "AI Agent"}</strong>
                        {msg.decision && <Badge>{msg.decision}</Badge>}
                        <span className="timestamp">{msg.timestamp || "Just now"}</span>
                      </div>

                      {/* TrustGuard Security Card */}
                      {msg.action && (
                        <div className={`trustguard-badge-card decision-${(msg.decision || "allow").toLowerCase()}`}>
                          <div className="badge-card-header">
                            <div className="badge-card-title">
                              <ShieldCheck size={16} />
                              <span>TrustGuard Runtime Authorization Evaluation</span>
                            </div>
                            <div className="badge-card-verdict">
                              <Risk score={msg.risk_score} />
                            </div>
                          </div>

                          <div className="badge-card-details">
                            <div><strong>Action:</strong> <code>{msg.action}</code></div>
                            <div><strong>Verdict:</strong> <Badge>{msg.decision}</Badge></div>
                            {msg.reason && <div><strong>Policy Reason:</strong> {msg.reason}</div>}
                          </div>

                          {/* Approval Interception Box */}
                          {msg.approval_id && (
                            <div className="badge-card-approval">
                              <div className="approval-notice">
                                <AlertTriangle size={15} style={{ color: "var(--warning)" }} />
                                <span>Approval Ticket <strong>#{msg.approval_id}</strong> is pending supervisor review in the Approval Center.</span>
                              </div>
                              <div className="approval-btn-group">
                                <button
                                  type="button"
                                  className="btn btn-sm btn-secondary"
                                  onClick={() => setPage("Approval Center")}
                                >
                                  Review in Approval Center
                                </button>
                                <button
                                  type="button"
                                  className="btn btn-sm btn-primary"
                                  disabled={chatExecPending === msg.approval_id}
                                  onClick={() => handleExecuteApproved(msg.approval_id)}
                                >
                                  {chatExecPending === msg.approval_id ? "Executing..." : "Execute Approved Action"}
                                </button>
                              </div>
                            </div>
                          )}
                        </div>
                      )}

                      {/* Message Text */}
                      <div className="bubble-content">
                        {msg.reply}
                      </div>

                      {/* Tool Payload (if available) */}
                      {msg.tool_result && (
                        <details className="tool-result-details">
                          <summary>View Executed Tool Payload ({msg.action})</summary>
                          <pre><code>{JSON.stringify(msg.tool_result, null, 2)}</code></pre>
                        </details>
                      )}
                    </div>
                  </div>
                ))
              )}
            </div>

            {/* Chat Input Field */}
            <form
              className="chatbot-input-bar"
              onSubmit={(e) => {
                e.preventDefault();
                handleSendChat();
              }}
            >
              <input
                type="text"
                className="form-input chat-input-field"
                placeholder="Ask this AI agent to perform an action (e.g. 'read report', 'transfer $5000', 'list users', 'delete user')..."
                value={chatInput}
                onChange={(e) => setChatInput(e.target.value)}
                disabled={chatSending}
              />
              <button
                type="submit"
                className="btn btn-primary chat-send-btn"
                disabled={chatSending || !chatInput.trim()}
              >
                <Send size={15} />
                {chatSending ? "Evaluating..." : "Send"}
              </button>
            </form>
          </section>
        )}

        {/* AGENTS TAB */}
        {page === "Agents" && (
          <section className="panel">
            <div className="panel-heading">
              <div>
                <h2>Independent Agent Identity Registry</h2>
                <p>
                  Eliminates shared API keys: each agent holds an independent identity with explicit permissions, mandatory prohibitions, and live quarantine status.
                </p>
              </div>
              <button className="btn btn-primary btn-sm" onClick={() => setShowAddAgent(!showAddAgent)}>
                <PlusCircle size={15} /> {showAddAgent ? "Cancel Registration" : "Register New AI Agent"}
              </button>
            </div>

            {showAddAgent && (
              <div className="panel-body" style={{ borderBottom: "1px solid transparent", background: "var(--surface)" }}>
                <form onSubmit={handleAddAgent}>
                  <h3 style={{ margin: "0 0 14px", fontSize: "14px" }}>Register Autonomous Agent Identity</h3>
                  <div className="form-grid">
                    <div className="form-group">
                      <label className="form-label">Agent Unique ID</label>
                      <input
                        className="form-input"
                        placeholder="e.g. agent-sales-06"
                        value={newAgent.agent_id}
                        onChange={(e) => setNewAgent({ ...newAgent, agent_id: e.target.value })}
                        required
                      />
                    </div>
                    <div className="form-group">
                      <label className="form-label">Agent Name</label>
                      <input
                        className="form-input"
                        placeholder="e.g. Sales Outreach Bot"
                        value={newAgent.name}
                        onChange={(e) => setNewAgent({ ...newAgent, name: e.target.value })}
                        required
                      />
                    </div>
                    <div className="form-group">
                      <label className="form-label">Operational Role / Domain</label>
                      <input
                        className="form-input"
                        placeholder="e.g. CRM & Customer Outreach"
                        value={newAgent.role}
                        onChange={(e) => setNewAgent({ ...newAgent, role: e.target.value })}
                      />
                    </div>
                  </div>
                  <div className="form-grid">
                    <div className="form-group">
                      <label className="form-label">Permitted Actions (comma-separated)</label>
                      <input
                        className="form-input"
                        value={newAgent.permissions}
                        onChange={(e) => setNewAgent({ ...newAgent, permissions: e.target.value })}
                        placeholder="read_report, list_users, export_data"
                      />
                    </div>
                    <div className="form-group">
                      <label className="form-label">Mandatory Prohibitions (non-overridable)</label>
                      <input
                        className="form-input"
                        value={newAgent.prohibited}
                        onChange={(e) => setNewAgent({ ...newAgent, prohibited: e.target.value })}
                        placeholder="delete_user, grant_admin, disable_mfa"
                      />
                    </div>
                  </div>
                  <button type="submit" className="btn btn-primary">Save & Issue Agent Identity</button>
                </form>
              </div>
            )}

            <div className="table-scroll">
              <table>
                <thead>
                  <tr>
                    <th>Agent ID</th>
                    <th>Identity Name</th>
                    <th>Role / Domain</th>
                    <th>Allowed Permissions</th>
                    <th>Mandatory Prohibitions</th>
                    <th>Status</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {agents.map((agent) => (
                    <tr key={agent.id}>
                      <td><code>{agent.id}</code></td>
                      <td><strong>{agent.name}</strong></td>
                      <td>{agent.role}</td>
                      <td style={{ maxWidth: "220px", fontSize: "10px" }}>{agent.permissions || "None"}</td>
                      <td style={{ maxWidth: "200px", fontSize: "10px", color: "var(--danger)" }}>{agent.prohibited || "None"}</td>
                      <td><Badge>{agent.status}</Badge></td>
                      <td>
                        {agent.status === "Quarantined" && (
                          <button
                            type="button"
                            className="btn btn-secondary btn-sm"
                            style={{ marginRight: "6px" }}
                            onClick={() =>
                              setQuarantineModalIncident({
                                agent_id: agent.id,
                                agent_name: agent.name,
                                action: "critical_quarantine_violation",
                                risk_score: 95,
                                reasons: [
                                  "Critical Policy Violation: Security anomaly detected",
                                  "Autonomous containment policy active",
                                ],
                                timestamp: new Date().toISOString(),
                                origin_ip: "Quarantined Session",
                                prompt_payload: `Security incident review for agent ${agent.name} (${agent.id}). Permissions: ${agent.permissions || "None"}. Prohibitions: ${agent.prohibited || "None"}.`,
                              })
                            }
                          >
                            Review Incident
                          </button>
                        )}
                        <button
                          className={agent.status === "Quarantined" ? "btn btn-secondary btn-sm" : "btn btn-quarantine btn-sm"}
                          onClick={() => toggleQuarantine(agent.id)}
                        >
                          {agent.status === "Quarantined" ? "Reactivate Agent" : "Quarantine Agent"}
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {!agents.length && <div className="empty">No agents registered in the database.</div>}
            </div>
          </section>
        )}

        {/* SECURITY EVENTS TAB */}
        {page === "Security Events" && (
          <section className="panel">
            <div className="panel-heading">
              <div>
                <h2>Continuous Authorization Event Log</h2>
                <p>Every single sensitive or routine action is logged with dynamic risk scoring and policy verdict</p>
              </div>
              <button className="btn btn-secondary btn-sm" onClick={refresh}>
                <RefreshCw size={13} /> Refresh Log
              </button>
            </div>
            <EventTable
              events={events}
              onReviewQuarantine={(event) =>
                setQuarantineModalIncident({
                  agent_id: event.agent_id,
                  agent_name: event.agent_name || event.agent_id,
                  action: event.action,
                  risk_score: event.risk_score || 90,
                  reasons: event.reason ? [event.reason] : ["Critical Authorization Violation"],
                  timestamp: event.timestamp,
                  origin_ip: "Intercepted by TrustGuard Runtime Policy Engine",
                  prompt_payload: `Security incident review for agent ${event.agent_name || event.agent_id} (${event.agent_id}). Action: ${event.action}. Risk: ${event.risk_score}.`,
                })
              }
            />
          </section>
        )}

        {/* APPROVAL CENTER TAB */}
        {page === "Approval Center" && (
          <section className="panel">
            <div className="panel-heading">
              <div>
                <h2>Human-In-The-Loop Approval Center</h2>
                <p>Sensitive actions held by the policy engine requiring supervisor authorization before execution</p>
              </div>
              <Badge>{approvals.length} pending</Badge>
            </div>
            <ApprovalTable approvals={approvals} busyId={busyId} onReview={review} />
          </section>
        )}

        {/* POLICIES & SANDBOX TAB */}
        {page === "Policies & Sandbox" && (
          <>
            {/* Threshold Configuration */}
            <section className="panel">
              <div className="panel-heading">
                <div>
                  <h2>Continuous Authorization Policy Thresholds</h2>
                  <p>Fine-tune risk score boundaries for Allow, Approval, Deny, and Quarantine</p>
                </div>
              </div>
              <div className="panel-body">
                <form onSubmit={handleUpdateThresholds}>
                  <div className="form-grid">
                    <div className="threshold-card">
                      <div className="threshold-title">Approval Threshold (Score &ge;)</div>
                      <input
                        type="number"
                        className="form-input"
                        value={thresholds.approval_threshold}
                        onChange={(e) => setThresholds({ ...thresholds, approval_threshold: e.target.value })}
                        min={0}
                        max={100}
                      />
                      <small style={{ color: "var(--muted)", display: "block", marginTop: "6px" }}>
                        Actions with risk &ge; this value trigger Human-in-the-Loop review.
                      </small>
                    </div>

                    <div className="threshold-card">
                      <div className="threshold-title">Denial Threshold (Score &ge;)</div>
                      <input
                        type="number"
                        className="form-input"
                        value={thresholds.risk_threshold}
                        onChange={(e) => setThresholds({ ...thresholds, risk_threshold: e.target.value })}
                        min={0}
                        max={100}
                      />
                      <small style={{ color: "var(--muted)", display: "block", marginTop: "6px" }}>
                        Actions with risk &ge; this value are automatically denied.
                      </small>
                    </div>

                    <div className="threshold-card">
                      <div className="threshold-title">Quarantine Threshold (Score &ge;)</div>
                      <input
                        type="number"
                        className="form-input"
                        value={thresholds.quarantine_threshold}
                        onChange={(e) => setThresholds({ ...thresholds, quarantine_threshold: e.target.value })}
                        min={0}
                        max={100}
                      />
                      <small style={{ color: "var(--muted)", display: "block", marginTop: "6px" }}>
                        Critical anomalies immediately isolate the agent from all systems.
                      </small>
                    </div>
                  </div>
                  <button type="submit" className="btn btn-primary">Save Policy Thresholds</button>
                </form>
              </div>
            </section>

            {/* Interactive Continuous Authorization Simulator */}
            <section className="panel">
              <div className="panel-heading">
                <div>
                  <h2>Interactive Continuous Authorization Simulator</h2>
                  <p>Simulate an AI agent attempting an action under varying runtime context and threat indicators</p>
                </div>
              </div>
              <div className="panel-body">
                <form onSubmit={handleEvaluateCustom}>
                  <div className="form-grid">
                    <div className="form-group">
                      <label className="form-label">Subject Agent Identity</label>
                      <select
                        className="form-select"
                        value={evalAgentId}
                        onChange={(e) => setEvalAgentId(e.target.value)}
                      >
                        {agents.map((a) => (
                          <option key={a.id} value={a.id}>
                            {a.name} ({a.id}) - [{a.status}]
                          </option>
                        ))}
                      </select>
                    </div>

                    <div className="form-group">
                      <label className="form-label">Requested Action</label>
                      <input
                        className="form-input"
                        value={evalAction}
                        onChange={(e) => setEvalAction(e.target.value)}
                        placeholder="e.g. transfer_funds, export_data, read_report"
                        required
                      />
                      <div style={{ display: "flex", gap: "6px", flexWrap: "wrap", marginTop: "6px" }}>
                        {["read_report", "transfer_funds", "export_data", "delete_user", "grant_admin", "install_software"].map((act) => (
                          <button
                            type="button"
                            key={act}
                            className="link-button"
                            style={{ fontSize: "10px", padding: "2px 6px", background: "var(--surface)", borderRadius: "12px" }}
                            onClick={() => setEvalAction(act)}
                          >
                            {act}
                          </button>
                        ))}
                      </div>
                    </div>
                  </div>

                  <div className="form-label" style={{ marginTop: "12px" }}>Runtime Context & Threat Signals</div>
                  <div className="checkbox-grid">
                    <label className="checkbox-item">
                      <input
                        type="checkbox"
                        checked={evalMeta.privileged}
                        onChange={(e) => setEvalMeta({ ...evalMeta, privileged: e.target.checked })}
                      />
                      Privileged Context (+20)
                    </label>

                    <label className="checkbox-item">
                      <input
                        type="checkbox"
                        checked={evalMeta.external_source}
                        onChange={(e) => setEvalMeta({ ...evalMeta, external_source: e.target.checked })}
                      />
                      External / Untrusted IP (+15)
                    </label>

                    <label className="checkbox-item">
                      <input
                        type="checkbox"
                        checked={evalMeta.new_device}
                        onChange={(e) => setEvalMeta({ ...evalMeta, new_device: e.target.checked })}
                      />
                      New / Abnormal Device (+15)
                    </label>

                    <label className="checkbox-item">
                      <input
                        type="checkbox"
                        checked={evalMeta.high_impact}
                        onChange={(e) => setEvalMeta({ ...evalMeta, high_impact: e.target.checked })}
                      />
                      High Impact Batch Operation (+20)
                    </label>

                    <label className="checkbox-item">
                      <input
                        type="checkbox"
                        checked={evalMeta.out_of_hours}
                        onChange={(e) => setEvalMeta({ ...evalMeta, out_of_hours: e.target.checked })}
                      />
                      Out-Of-Hours Execution (+10)
                    </label>

                    <label className="checkbox-item">
                      <input
                        type="checkbox"
                        checked={evalMeta.admin_action}
                        onChange={(e) => setEvalMeta({ ...evalMeta, admin_action: e.target.checked })}
                      />
                      Admin Escalation Attempt (+15)
                    </label>
                  </div>

                  <button type="submit" className="btn btn-primary" disabled={evaluating}>
                    <ShieldCheck size={16} />
                    {evaluating ? "Evaluating..." : "Evaluate Continuous Authorization"}
                  </button>
                </form>

                {evalResult && (
                  <div className="result-card">
                    <div className="result-header">
                      <div className="result-title">
                        <span>Evaluation Verdict:</span>
                        <Badge>{evalResult.decision}</Badge>
                      </div>
                      <div className="result-score">
                        Calculated Risk Score: <strong>{evalResult.risk_score} / 100</strong>
                      </div>
                    </div>
                    <div style={{ fontSize: "12px", color: "var(--muted-strong)", lineHeight: 1.6 }}>
                      {evalResult.reason && evalResult.reason.map((r, i) => (
                        <div key={i}>• {r}</div>
                      ))}
                    </div>
                    <div style={{ marginTop: "12px", fontSize: "11px", color: "var(--muted)" }}>
                      Approval Required: <strong>{evalResult.approval_required ? "Yes (Held in Approval Center)" : "No"}</strong> ·
                      Restriction: <strong>{evalResult.restriction}</strong>
                    </div>
                  </div>
                )}
              </div>
            </section>
          </>
        )}

        <footer className="footer">
          TRUST BUT VERIFY · CONTINUOUS AUTHORIZATION FOR AUTONOMOUS AGENT WORKFLOWS · 2026
        </footer>
      </main>

      {/* Quarantine Incident Modal */}
      <QuarantineModal
        isOpen={!!quarantineModalIncident}
        onClose={() => setQuarantineModalIncident(null)}
        incident={quarantineModalIncident}
        onReactivate={async (agentId) => {
          await toggleQuarantine(agentId);
          setQuarantineModalIncident(null);
        }}
        onConfirmQuarantine={() => {
          setQuarantineModalIncident(null);
        }}
      />
    </div>
    </>
  );
}
