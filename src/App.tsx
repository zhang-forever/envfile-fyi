import { useState, useCallback, useRef } from "react";

type Severity = "critical" | "high" | "medium" | "low";

interface KeyPattern {
  name: string;
  pattern: RegExp;
  severity: Severity;
  description: string;
  category: string;
}

const KEY_PATTERNS: KeyPattern[] = [
  // Cloud providers
  { name: "AWS Access Key", pattern: /^AKIA[0-9A-Z]{16}$/, severity: "critical", description: "Grants AWS API access. Revoke immediately if exposed.", category: "Cloud" },
  { name: "AWS Secret Key", pattern: /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[A-Za-z0-9/+]{40}$/, severity: "critical", description: "AWS secret access key. Rotate immediately.", category: "Cloud" },
  { name: "Azure Storage Account Key", pattern: /^AccountKey=[A-Za-z0-9+/=]{88}$/, severity: "critical", description: "Azure storage account key. Regenerate in Azure Portal.", category: "Cloud" },
  { name: "Azure Client Secret", pattern: /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[A-Za-z0-9]{34,40}$/, severity: "high", description: "Possible Azure AD client secret.", category: "Cloud" },
  { name: "GCP Service Account Key", pattern: /^-----BEGIN (RSA )?PRIVATE KEY-----$/m, severity: "critical", description: "GCP service account private key. Revoke via GCP Console.", category: "Cloud" },
  { name: "Google API Key", pattern: /^AIza[0-9A-Za-z_-]{35}$/, severity: "high", description: "Google API key. Restrict by IP/referrer.", category: "Cloud" },
  { name: "Heroku API Key", pattern: /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/, severity: "medium", description: "Possible Heroku API key. Verify in Heroku dashboard.", category: "Cloud" },

  // Payment
  { name: "Stripe Secret Key", pattern: /^sk_live_[0-9a-zA-Z]{24,}$/, severity: "critical", description: "Stripe production secret key. Revoke via Stripe dashboard.", category: "Payment" },
  { name: "Stripe Test Key", pattern: /^sk_test_[0-9a-zA-Z]{24,}$/, severity: "medium", description: "Stripe test key (not production, but keep private).", category: "Payment" },
  { name: "Stripe Restricted Key", pattern: /^rk_(live|test)_[0-9a-zA-Z]{24,}$/, severity: "high", description: "Stripe restricted API key.", category: "Payment" },
  { name: "PayPal Client Secret", pattern: /^EF[A-Za-z0-9_-]{50,}$/, severity: "high", description: "Possible PayPal client secret.", category: "Payment" },
  { name: "Square Access Token", pattern: /^(sq0atp-|sq0csp-)[A-Za-z0-9_-]{22,}$/, severity: "critical", description: "Square access token. Revoke in Square Developer Dashboard.", category: "Payment" },

  // Social / Dev platforms
  { name: "GitHub PAT (classic)", pattern: /^ghp_[a-zA-Z0-9]{36,}$/, severity: "critical", description: "GitHub personal access token.", category: "Dev" },
  { name: "GitHub Actions Token", pattern: /^ghs_[a-zA-Z0-9]{36,}$/, severity: "critical", description: "GitHub Actions secret.", category: "Dev" },
  { name: "GitHub OAuth Token", pattern: /^gho_[a-zA-Z0-9]{36,}$/, severity: "critical", description: "GitHub OAuth token.", category: "Dev" },
  { name: "GitHub Refresh Token", pattern: /^ghr_[a-zA-Z0-9]{36,}$/, severity: "critical", description: "GitHub refresh token.", category: "Dev" },
  { name: "GitLab Token", pattern: /^glpat-[a-zA-Z0-9_-]{20,}$/, severity: "critical", description: "GitLab personal access token.", category: "Dev" },
  { name: "Bitbucket App Password", pattern: /^[a-zA-Z0-9]{20}$/, severity: "medium", description: "Possible Bitbucket app password (short token).", category: "Dev" },
  { name: "npm Token", pattern: /^npm_[A-Za-z0-9]{36}$/, severity: "critical", description: "npm access token. Revoke at npmjs.com/settings/tokens.", category: "Dev" },
  { name: "PyPI Token", pattern: /^pypi-[A-Za-z0-9_-]{50,}$/, severity: "critical", description: "PyPI API token. Revoke at pypi.org/manage/account/token-settings.", category: "Dev" },
  { name: "npm Automation Token", pattern: /^npm_[a-zA-Z0-9]{36}$/, severity: "critical", description: "npm automation token.", category: "Dev" },

  // Communication
  { name: "Slack Webhook", pattern: /^https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9/]+$/, severity: "high", description: "Slack webhook URL. Can post messages to channels.", category: "Comm" },
  { name: "Slack Bot Token", pattern: /^xoxb-[0-9]{11,}-[A-Za-z0-9-]{24,}$/, severity: "critical", description: "Slack bot token. Revoke via Slack admin.", category: "Comm" },
  { name: "Slack User Token", pattern: /^xoxp-[0-9]{11,}-[A-Za-z0-9-]{24,}$/, severity: "critical", description: "Slack user token. Revoke via Slack admin.", category: "Comm" },
  { name: "Discord Webhook", pattern: /^https:\/\/discord\.com\/api\/webhooks\/[0-9]+\/[A-Za-z0-9_-]+$/, severity: "high", description: "Discord webhook. Can send messages.", category: "Comm" },
  { name: "Discord Bot Token", pattern: /^N[A-Za-z0-9_-]{23,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{27,}$/, severity: "critical", description: "Discord bot token. Regenerate in Discord Developer Portal.", category: "Comm" },
  { name: "Telegram Bot Token", pattern: /^[0-9]{8,10}:[A-Za-z0-9_-]{35}$/, severity: "high", description: "Telegram bot token. Revoke via @BotFather.", category: "Comm" },
  { name: "Twilio Account SID", pattern: /^AC[a-f0-9]{32}$/, severity: "high", description: "Twilio Account SID. Pair with API key for full access.", category: "Comm" },
  { name: "Twilio API Key", pattern: /^SK[a-f0-9]{32}$/, severity: "critical", description: "Twilio API key. Revoke in Twilio Console.", category: "Comm" },

  // Email / Mail
  { name: "SendGrid API Key", pattern: /^SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}$/, severity: "critical", description: "SendGrid API key. Revoke at sendgrid.com.", category: "Email" },
  { name: "Mailgun API Key", pattern: /^key-[0-9a-zA-Z]{32}$/, severity: "high", description: "Mailgun API key. Rotate in Mailgun dashboard.", category: "Email" },
  { name: "Mailgun Public Key", pattern: /^pubkey-[0-9a-zA-Z]{32}$/, severity: "medium", description: "Mailgun public key. Low risk but keep private.", category: "Email" },

  // AI / ML
  { name: "OpenAI API Key", pattern: /^sk-[A-Za-z0-9]{48,}$/, severity: "critical", description: "OpenAI API key. Rotate at platform.openai.com.", category: "AI" },
  { name: "Anthropic API Key", pattern: /^sk-ant-[A-Za-z0-9_-]{40,}$/, severity: "critical", description: "Anthropic Claude API key.", category: "AI" },
  { name: "Cohere API Key", pattern: /^[A-Za-z0-9]{40}$/, severity: "medium", description: "Possible Cohere API key (40-char alphanumeric).", category: "AI" },
  { name: "Hugging Face Token", pattern: /^hf_[A-Za-z0-9]{34,}$/, severity: "critical", description: "Hugging Face API token.", category: "AI" },
  { name: "Replicate API Token", pattern: /^r8_[A-Za-z0-9]{40}$/, severity: "critical", description: "Replicate API token.", category: "AI" },
  { name: "Vercel Token", pattern: /^vrsl_[A-Za-z0-9]{24,}$/, severity: "critical", description: "Vercel access token.", category: "AI" },

  // General secrets
  { name: "JWT Token", pattern: /^eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}$/, severity: "high", description: "JSON Web Token. May contain sensitive claims.", category: "General" },
  { name: "Private Key", pattern: /^-----BEGIN (RSA |EC |DSA |ED25519 )?PRIVATE KEY-----$/m, severity: "critical", description: "Private key. Never share. Regenerate immediately.", category: "General" },
  { name: "PGP Private Key", pattern: /^-----BEGIN PGP PRIVATE KEY BLOCK-----$/m, severity: "critical", description: "PGP private key block.", category: "General" },
  { name: "SSH Private Key", pattern: /^-----BEGIN OPENSSH PRIVATE KEY-----$/m, severity: "critical", description: "SSH private key. Regenerate and update authorized_keys.", category: "General" },
  { name: "Database Connection URL", pattern: /^(postgres|mysql|mongodb|redis|amqp|rabbitmq):\/\/[^@\s]+@[^/\s]+/, severity: "critical", description: "Database connection string with credentials.", category: "General" },
  { name: "URL with Embedded Password", pattern: /^https?:\/\/[^:]+:[^@]+@/, severity: "critical", description: "URL with embedded credentials in plain text.", category: "General" },
  { name: "Base64 Encoded Secret (long)", pattern: /^[A-Za-z0-9+/]{100,}={0,2}$/, severity: "medium", description: "Long base64 string. Could be an encoded secret.", category: "General" },
  { name: "Hex Encoded Secret (long)", pattern: /^[0-9a-fA-F]{64,}$/, severity: "medium", description: "Long hex string. Could be a hash or encoded secret.", category: "General" },
  { name: "Bearer Token", pattern: /^Bearer\s+[A-Za-z0-9._-]{20,}$/, severity: "high", description: "Bearer authentication token.", category: "General" },
  { name: "Basic Auth Header", pattern: /^Basic\s+[A-Za-z0-9+/=]{20,}$/, severity: "high", description: "HTTP Basic Auth header with encoded credentials.", category: "General" },

  // Informational
  { name: "IP Address", pattern: /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/, severity: "low", description: "IP address. Usually low risk but could be internal.", category: "Info" },
  { name: "Email Address", pattern: /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/, severity: "low", description: "Email address. Consider if it should be public.", category: "Info" },
  { name: "Phone Number", pattern: /^\+?[1-9]\d{6,14}$/, severity: "low", description: "Phone number in E.164 format.", category: "Info" },
];

function analyzeKey(value: string): KeyPattern[] {
  if (!value || value.length < 5) return [];
  const results: KeyPattern[] = [];
  for (const p of KEY_PATTERNS) {
    try {
      if (p.pattern.test(value)) {
        results.push({ ...p });
      }
    } catch {
      // Skip patterns that fail regex compilation
    }
  }
  return results;
}

const SEVERITY_ORDER: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3 };
const SEVERITY_COLORS: Record<Severity, { bg: string; fg: string; border: string }> = {
  critical: { bg: "#fef2f2", fg: "#dc2626", border: "#fca5a5" },
  high: { bg: "#fff7ed", fg: "#ea580c", border: "#fdba74" },
  medium: { bg: "#fefce8", fg: "#ca8a04", border: "#fde047" },
  low: { bg: "#f0fdf4", fg: "#16a34a", border: "#86efac" },
};
const SEVERITY_LABELS: Record<Severity, string> = {
  critical: "🔴 CRITICAL",
  high: "🟠 HIGH",
  medium: "🟡 MEDIUM",
  low: "🟢 LOW",
};

export default function App() {
  const [entries, setEntries] = useState<{ key: string; value: string; results: KeyPattern[] }[]>([]);
  const [dragOver, setDragOver] = useState(false);
  const [fileName, setFileName] = useState<string | null>(null);
  const fileRef = useRef<HTMLInputElement>(null);

  const parseEnv = useCallback((text: string, name?: string) => {
    setFileName(name ?? null);
    const lines = text.split("\n").filter((l) => l.trim() && !l.trim().startsWith("#"));
    const parsed = lines
      .map((line) => {
        const eq = line.indexOf("=");
        if (eq === -1) return null;
        const key = line.slice(0, eq).trim();
        if (!key || key.includes(" ")) return null;
        const raw = line.slice(eq + 1);
        // Strip surrounding quotes (single or double)
        let val = raw.trim();
        if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
          val = val.slice(1, -1);
        }
        return { key, value: val, results: analyzeKey(val) };
      })
      .filter(Boolean) as { key: string; value: string; results: KeyPattern[] }[];
    setEntries(parsed);
  }, []);

  const onDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      setDragOver(false);
      const file = e.dataTransfer.files[0];
      if (!file) return;
      const reader = new FileReader();
      reader.onload = () => parseEnv(reader.result as string, file.name);
      reader.readAsText(file);
    },
    [parseEnv]
  );

  const onFilePick = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      const file = e.target.files?.[0];
      if (!file) return;
      const reader = new FileReader();
      reader.onload = () => parseEnv(reader.result as string, file.name);
      reader.readAsText(file);
    },
    [parseEnv]
  );

  const generateExample = () => {
    const lines = entries.map((e) => {
      if (e.results.length > 0) {
        const placeholder = e.key
          .toLowerCase()
          .replace(/[^a-z0-9]/g, "_")
          .replace(/_+/g, "_");
        return `# ⚠️  Replace with actual value (detected: ${e.results.map((r) => r.name).join(", ")})\n${placeholder}=`;
      }
      return `${e.key}=${e.value}`;
    });
    const blob = new Blob([lines.join("\n") + "\n"], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = ".env.example";
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const critical = entries.filter((e) => e.results.some((r) => r.severity === "critical")).length;
  const high = entries.filter((e) => e.results.some((r) => r.severity === "high")).length;
  const medium = entries.filter((e) => e.results.some((r) => r.severity === "medium")).length;
  const low = entries.filter((e) => e.results.some((r) => r.severity === "low")).length;
  const clean = entries.filter((e) => e.results.length === 0).length;
  const flagged = entries.filter((e) => e.results.length > 0).length;

  const worstSeverity = (): Severity | null => {
    if (critical > 0) return "critical";
    if (high > 0) return "high";
    if (medium > 0) return "medium";
    if (low > 0) return "low";
    return null;
  };

  const worst = worstSeverity();

  return (
    <div style={{ maxWidth: 800, margin: "0 auto", padding: 32, fontFamily: "system-ui, -apple-system, sans-serif", color: "#1a1a1a" }}>
      {/* Header */}
      <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 8 }}>
        <span style={{ fontSize: 32 }}>🔐</span>
        <h1 style={{ fontSize: 28, fontWeight: 800, margin: 0 }}>envfile.fyi</h1>
      </div>
      <p style={{ color: "#666", marginBottom: 28, lineHeight: 1.5, fontSize: 15 }}>
        Drag a <code style={{ background: "#f3f4f6", padding: "2px 6px", borderRadius: 4 }}>.env</code> file to audit it.
        All analysis happens <strong>in your browser</strong> — nothing leaves your machine.
      </p>

      {/* Drop zone */}
      <div
        onDragOver={(e) => {
          e.preventDefault();
          setDragOver(true);
        }}
        onDragLeave={() => setDragOver(false)}
        onDrop={onDrop}
        onClick={() => fileRef.current?.click()}
        style={{
          border: `2px dashed ${dragOver ? "#2563eb" : entries.length > 0 ? (worst && SEVERITY_COLORS[worst].border) : "#d1d5db"}`,
          borderRadius: 16,
          padding: entries.length > 0 ? "20px 24px" : 56,
          textAlign: "center",
          cursor: "pointer",
          background: dragOver ? "#eff6ff" : entries.length > 0 ? "#fafafa" : "#fff",
          marginBottom: 28,
          transition: "all 0.2s ease",
          position: "relative",
        }}
      >
        <input ref={fileRef} type="file" accept=".env,.txt,.env.*" onChange={onFilePick} style={{ display: "none" }} />

        {entries.length === 0 ? (
          <>
            <div style={{ fontSize: 48, marginBottom: 12 }}>📄</div>
            <p style={{ color: "#6b7280", fontSize: 16, margin: 0 }}>
              Drop <strong>.env</strong> file here, or click to browse
            </p>
            <p style={{ color: "#9ca3af", fontSize: 13, marginTop: 8, margin: "8px 0 0" }}>
              Supports .env, .env.local, .env.production, etc.
            </p>
          </>
        ) : (
          <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 12 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <span style={{ fontSize: 20 }}>📋</span>
              <span style={{ fontSize: 16, fontWeight: 600 }}>
                {fileName && (
                  <span style={{ color: "#374151", marginRight: 8 }}>{fileName}</span>
                )}
                {entries.length} keys scanned
              </span>
            </div>

            {/* Summary badges */}
            <div style={{ display: "flex", gap: 8, flexWrap: "wrap", justifyContent: "center" }}>
              {flagged > 0 && (
                <span
                  style={{
                    padding: "6px 14px",
                    borderRadius: 20,
                    fontSize: 13,
                    fontWeight: 700,
                    background: "#fef2f2",
                    color: "#dc2626",
                    border: "1px solid #fca5a5",
                  }}
                >
                  ⚠️ {flagged} flagged
                </span>
              )}
              {critical > 0 && (
                <span style={{ padding: "6px 14px", borderRadius: 20, fontSize: 13, fontWeight: 700, background: "#fef2f2", color: "#dc2626", border: "1px solid #fca5a5" }}>
                  🔴 {critical} critical
                </span>
              )}
              {high > 0 && (
                <span style={{ padding: "6px 14px", borderRadius: 20, fontSize: 13, fontWeight: 700, background: "#fff7ed", color: "#ea580c", border: "1px solid #fdba74" }}>
                  🟠 {high} high
                </span>
              )}
              {medium > 0 && (
                <span style={{ padding: "6px 14px", borderRadius: 20, fontSize: 13, fontWeight: 700, background: "#fefce8", color: "#ca8a04", border: "1px solid #fde047" }}>
                  🟡 {medium} medium
                </span>
              )}
              {clean > 0 && (
                <span style={{ padding: "6px 14px", borderRadius: 20, fontSize: 13, fontWeight: 700, background: "#f0fdf4", color: "#16a34a", border: "1px solid #86efac" }}>
                  ✅ {clean} clean
                </span>
              )}
            </div>

            {/* Overall risk assessment */}
            {worst && (
              <div
                style={{
                  padding: "8px 16px",
                  borderRadius: 8,
                  fontSize: 13,
                  fontWeight: 600,
                  background: SEVERITY_COLORS[worst].bg,
                  color: SEVERITY_COLORS[worst].fg,
                  border: `1px solid ${SEVERITY_COLORS[worst].border}`,
                }}
              >
                Overall risk: {SEVERITY_LABELS[worst]}
              </div>
            )}

            <div style={{ display: "flex", gap: 8, marginTop: 4 }}>
              <button
                onClick={(e) => {
                  e.stopPropagation();
                  generateExample();
                }}
                style={{
                  padding: "10px 20px",
                  background: "#2563eb",
                  color: "#fff",
                  border: "none",
                  borderRadius: 8,
                  cursor: "pointer",
                  fontSize: 14,
                  fontWeight: 600,
                  display: "flex",
                  alignItems: "center",
                  gap: 6,
                }}
              >
                📥 Download .env.example
              </button>
              <button
                onClick={(e) => {
                  e.stopPropagation();
                  setEntries([]);
                  setFileName(null);
                  if (fileRef.current) fileRef.current.value = "";
                }}
                style={{
                  padding: "10px 20px",
                  background: "#f3f4f6",
                  color: "#374151",
                  border: "1px solid #d1d5db",
                  borderRadius: 8,
                  cursor: "pointer",
                  fontSize: 14,
                  fontWeight: 500,
                }}
              >
                Clear
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Entries list */}
      {entries.map((e) => {
        const topSeverity = e.results.length > 0 ? e.results.reduce((acc, r) => (SEVERITY_ORDER[r.severity] < SEVERITY_ORDER[acc] ? r.severity : acc), "low" as Severity) : null;
        const colors = topSeverity ? SEVERITY_COLORS[topSeverity] : null;

        return (
          <div
            key={e.key}
            style={{
              padding: "14px 16px",
              marginBottom: 2,
              borderRadius: e.results.length > 0 ? 10 : 8,
              borderLeft: e.results.length > 0 && colors ? `4px solid ${colors.fg}` : "4px solid transparent",
              background: e.results.length > 0 ? colors?.bg : "#fafafa",
              transition: "all 0.15s ease",
            }}
          >
            <div style={{ display: "flex", gap: 8, alignItems: "center", marginBottom: e.results.length > 0 ? 8 : 0 }}>
              <code
                style={{
                  fontWeight: 700,
                  fontSize: 13,
                  color: e.results.length > 0 ? colors?.fg : "#374151",
                  background: e.results.length > 0 ? "rgba(255,255,255,0.6)" : "#f3f4f6",
                  padding: "2px 8px",
                  borderRadius: 4,
                }}
              >
                {e.key}
              </code>
              <span style={{ color: "#d1d5db" }}>→</span>
              <code
                style={{
                  fontSize: 12,
                  color: "#6b7280",
                  overflow: "hidden",
                  textOverflow: "ellipsis",
                  whiteSpace: "nowrap",
                  flex: 1,
                  background: "rgba(255,255,255,0.5)",
                  padding: "2px 6px",
                  borderRadius: 4,
                }}
              >
                {e.value.length > 60 ? e.value.slice(0, 60) + "…" : e.value || "(empty)"}
              </code>
              {e.results.length > 0 && (
                <span
                  style={{
                    fontSize: 11,
                    fontWeight: 700,
                    color: colors?.fg,
                    background: "rgba(255,255,255,0.7)",
                    padding: "2px 8px",
                    borderRadius: 10,
                    whiteSpace: "nowrap",
                  }}
                >
                  {SEVERITY_LABELS[topSeverity!].split(" ").pop()}
                </span>
              )}
            </div>

            {e.results.map((r, i) => (
              <div
                key={i}
                style={{
                  marginTop: 4,
                  padding: "6px 10px",
                  borderRadius: 6,
                  fontSize: 12,
                  display: "inline-flex",
                  alignItems: "center",
                  gap: 6,
                  marginRight: 6,
                  marginBottom: 2,
                  background: SEVERITY_COLORS[r.severity].bg,
                  color: SEVERITY_COLORS[r.severity].fg,
                  border: `1px solid ${SEVERITY_COLORS[r.severity].border}`,
                  fontWeight: r.severity === "critical" ? 700 : 500,
                }}
              >
                <span style={{ fontSize: 10 }}>{SEVERITY_LABELS[r.severity].split(" ")[0]}</span>
                <strong>{r.name}</strong>
                <span style={{ opacity: 0.8 }}>— {r.description}</span>
              </div>
            ))}
          </div>
        );
      })}

      {/* Footer */}
      <div style={{ marginTop: 40, paddingTop: 20, borderTop: "1px solid #e5e7eb", textAlign: "center", color: "#9ca3af", fontSize: 13 }}>
        <p style={{ margin: 0 }}>
          100% client-side analysis • Detected {KEY_PATTERNS.length} key patterns • No data leaves your browser
        </p>
      </div>
    </div>
  );
}
