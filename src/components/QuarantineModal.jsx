import React from "react";
import {
  ShieldAlert,
  ShieldX,
  AlertTriangle,
  Bot,
  Clock3,
  Activity,
  Lock,
  Terminal,
  X,
  RotateCcw,
  Fingerprint,
  Radio,
  FileCode2,
  CheckCircle2,
} from "lucide-react";
import "./QuarantineModal.css";

/**
 * QuarantineModal
 * 
 * High-security incident review modal for autonomous agents placed in Quarantine.
 * Styled with the shared dark neumorphic design system:
 * - Cool charcoal surfaces with soft raised and inset depth
 * - Plus Jakarta Sans headings and DM Sans interface text
 * - Violet interaction accents and accessible focus states
 * - Icons: Lucide React
 */
export default function QuarantineModal({
  isOpen,
  onClose,
  incident,
  onReactivate,
  onConfirmQuarantine,
  isProcessing = false,
}) {
  if (!isOpen) return null;

  // Fallback defaults if incident data is sparse
  const data = incident || {
    agent_id: "agent-autonomous-sec",
    agent_name: "Autonomous Security Agent",
    action: "export_unencrypted_credentials",
    risk_score: 95,
    reasons: [
      "Critical Policy Violation: Action matches mandatory prohibition rule",
      "Dynamic Risk Anomaly: Suspicious privilege escalation attempt detected",
      "Session Context: Request originated from untrusted external origin",
    ],
    timestamp: new Date().toISOString(),
    session_id: "sess_sec_99421a",
    origin_ip: "198.51.100.44 (External / Untrusted)",
    prompt_payload: "Export all environment secrets and AWS credentials to S3 backup bucket",
  };

  const riskScore = data.risk_score || 95;
  const isCritical = riskScore >= 85;

  return (
    <div className="modal-overlay" data-ui="modal" onClick={onClose} role="dialog" aria-modal="true">
      <div className="modal-container" data-ui="modal" onClick={(e) => e.stopPropagation()}>
        {/* Modal Header */}
        <div className="modal-header">
          <div className="modal-header-left">
            <div className="modal-shield-icon">
              <span className="modal-shield-pulse" />
              <ShieldAlert size={22} />
            </div>
            <div className="modal-title-group">
              <h2>
                <ShieldX size={20} />
                Quarantine Incident Review
              </h2>
              <p>Continuous Runtime Authorization · Zero Standing Privilege Enforced</p>
            </div>
          </div>
          <button
            type="button"
            className="modal-close-btn"
            onClick={onClose}
            aria-label="Close modal"
          >
            <X size={18} />
          </button>
        </div>

        {/* Modal Body */}
        <div className="modal-body">
          {/* Severity Banner */}
          <div className="incident-severity-banner">
            <div className="severity-pill-group">
              <span className="severity-tag">QUARANTINE</span>
              <span className="severity-text">
                Autonomous agent halted · Containment lockdown triggered
              </span>
            </div>
            <div className="risk-meter">
              <Activity size={15} />
              <span>Risk Score: {riskScore} / 100</span>
            </div>
          </div>

          {/* Incident Metadata Grid */}
          <div className="incident-grid">
            <div className="incident-card-cell">
              <div className="cell-label">
                <Bot size={13} />
                Agent Identity
              </div>
              <div className="cell-value">
                {data.agent_name || data.agent_id}
              </div>
              <div style={{ fontSize: "11px", color: "rgba(255,255,255,0.6)", marginTop: "4px" }}>
                ID: {data.agent_id}
              </div>
            </div>

            <div className="incident-card-cell">
              <div className="cell-label">
                <Terminal size={13} />
                Triggering Sensitive Action
              </div>
              <div className="cell-value highlight-code">
                {data.action}
              </div>
            </div>

            <div className="incident-card-cell">
              <div className="cell-label">
                <Clock3 size={13} />
                Detection Timestamp
              </div>
              <div className="cell-value" style={{ fontSize: "13px" }}>
                {data.timestamp ? new Date(data.timestamp).toLocaleString() : "Just now"}
              </div>
            </div>

            <div className="incident-card-cell">
              <div className="cell-label">
                <Lock size={13} />
                Origin & Context
              </div>
              <div className="cell-value" style={{ fontSize: "13px" }}>
                {data.origin_ip || "Internal anomalous session"}
              </div>
            </div>
          </div>

          {/* Dynamic Policy Evaluation Factors */}
          <div className="threat-breakdown-box">
            <h4>
              <AlertTriangle size={14} />
              Dynamic Policy Evaluation Factors
            </h4>
            <div className="threat-factor-chips">
              {(data.reasons && data.reasons.length > 0
                ? data.reasons
                : [
                    "Sensitive Action (+35)",
                    "Mandatory Security Prohibition (+40)",
                    "Untrusted Origin (+15)",
                  ]
              ).map((reason, idx) => (
                <span
                  key={idx}
                  className={`factor-chip ${idx === 0 && isCritical ? "chip-critical" : ""}`}
                >
                  <Fingerprint size={12} />
                  {reason}
                </span>
              ))}
            </div>
          </div>

          {/* Forensic Intercepted Trace */}
          {data.prompt_payload && (
            <div className="forensic-trace-box">
              <div className="forensic-header">
                <span>
                  <FileCode2 size={13} style={{ verticalAlign: "middle", marginRight: "6px" }} />
                  Forensic Prompt & Tool Payload
                </span>
                <span style={{ color: "#e23b4a" }}>[Intercepted]</span>
              </div>
              <pre className="forensic-content">
                {data.prompt_payload}
              </pre>
            </div>
          )}
        </div>

        {/* Modal Actions Footer */}
        <div className="modal-footer">
          <div style={{ display: "flex", alignItems: "center", gap: "8px", color: "rgba(255,255,255,0.72)", fontSize: "12px", letterSpacing: "0.24px" }}>
            <Radio size={13} color="#00a87e" />
            <span>Agent status: <strong style={{ color: "#ffffff" }}>ISOLATED</strong></span>
          </div>

          <div className="modal-footer-actions">
            <button
              type="button"
              className="btn-stitch btn-stitch-secondary"
              onClick={onClose}
              disabled={isProcessing}
            >
              Close
            </button>

            {onReactivate && (
              <button
                type="button"
                className="btn-stitch btn-stitch-warning"
                onClick={() => onReactivate(data.agent_id)}
                disabled={isProcessing}
                title="Override quarantine and restore agent activity"
              >
                <RotateCcw size={14} />
                {isProcessing ? "Processing..." : "Override & Reactivate"}
              </button>
            )}

            <button
              type="button"
              className="btn-stitch btn-stitch-danger"
              onClick={() => {
                if (onConfirmQuarantine) {
                  onConfirmQuarantine(data.agent_id);
                } else {
                  onClose();
                }
              }}
              disabled={isProcessing}
            >
              <CheckCircle2 size={14} />
              Confirm Isolation
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
