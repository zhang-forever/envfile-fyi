import { useState, useCallback, useRef } from "react";

type FileEntry = { key: string; value: string; results: KeyPattern[] };
interface BulkFileResult {
  name: string;
  entries: FileEntry[];
}

type Severity = "critical" | "high" | "medium" | "low";

interface KeyPattern {
  name: string;
  pattern: RegExp;
  severity: Severity;
  description: string;
  category: string;
  fixSuggestion: string;
}

const KEY_PATTERNS: KeyPattern[] = [
  // Cloud providers
  { name: "AWS Access Key", pattern: /^AKIA[0-9A-Z]{16}$/, severity: "critical", description: "Grants AWS API access. Revoke immediately if exposed.", category: "Cloud", fixSuggestion: "Rotate the key in AWS IAM console → Users → Security credentials → Create new access key. Add old key to .env.example placeholder, delete from .env." },
  { name: "AWS Secret Key", pattern: /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[A-Za-z0-9/+]{40}$/, severity: "critical", description: "AWS secret access key. Rotate immediately.", category: "Cloud", fixSuggestion: "Rotate in AWS IAM console. Use AWS Secrets Manager or Parameter Store for production." },
  { name: "Azure Storage Account Key", pattern: /^AccountKey=[A-Za-z0-9+/=]{88}$/, severity: "critical", description: "Azure storage account key. Regenerate in Azure Portal.", category: "Cloud", fixSuggestion: "Regenerate key in Azure Portal → Storage Account → Access keys. Consider switching to Azure AD authentication." },
  { name: "Azure Client Secret", pattern: /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[A-Za-z0-9]{34,40}$/, severity: "high", description: "Possible Azure AD client secret.", category: "Cloud", fixSuggestion: "Rotate in Azure Portal → App registrations → Certificates & secrets. Use Managed Identity where possible." },
  { name: "GCP Service Account Key", pattern: /^-----BEGIN (RSA )?PRIVATE KEY-----$/m, severity: "critical", description: "GCP service account private key. Revoke via GCP Console.", category: "Cloud", fixSuggestion: "Delete the key in GCP Console → IAM → Service Accounts → Keys. Use Workload Identity or short-lived credentials instead." },
  { name: "Google API Key", pattern: /^AIza[0-9A-Za-z_-]{35}$/, severity: "high", description: "Google API key. Restrict by IP/referrer.", category: "Cloud", fixSuggestion: "Restrict the key in Google Cloud Console → APIs & Services → Credentials. Add application and API restrictions." },
  { name: "Heroku API Key", pattern: /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/, severity: "medium", description: "Possible Heroku API key. Verify in Heroku dashboard.", category: "Cloud", fixSuggestion: "Rotate at Heroku dashboard → Account settings → API Key. Use Heroku OAuth tokens instead." },

  // Payment
  { name: "Stripe Secret Key", pattern: /^sk_live_[0-9a-zA-Z]{24,}$/, severity: "critical", description: "Stripe production secret key. Revoke via Stripe dashboard.", category: "Payment", fixSuggestion: "Revoke at Stripe dashboard → Developers → API keys. Create a new restricted key with minimal permissions." },
  { name: "Stripe Test Key", pattern: /^sk_test_[0-9a-zA-Z]{24,}$/, severity: "medium", description: "Stripe test key (not production, but keep private).", category: "Payment", fixSuggestion: "Still rotate for security hygiene. Move to environment variables or secrets manager." },
  { name: "Stripe Restricted Key", pattern: /^rk_(live|test)_[0-9a-zA-Z]{24,}$/, severity: "high", description: "Stripe restricted API key.", category: "Payment", fixSuggestion: "Rotate in Stripe dashboard. Ensure restricted keys have minimum required permissions only." },
  { name: "PayPal Client Secret", pattern: /^EF[A-Za-z0-9_-]{50,}$/, severity: "high", description: "Possible PayPal client secret.", category: "Payment", fixSuggestion: "Rotate in PayPal Developer Dashboard → App credentials. Use Braintree vault for tokenization." },
  { name: "Square Access Token", pattern: /^(sq0atp-|sq0csp-)[A-Za-z0-9_-]{22,}$/, severity: "critical", description: "Square access token. Revoke in Square Developer Dashboard.", category: "Payment", fixSuggestion: "Revoke in Square Developer Dashboard → Credentials. Create OAuth flow for production tokens." },

  // Social / Dev platforms
  { name: "GitHub PAT (classic)", pattern: /^ghp_[a-zA-Z0-9]{36,}$/, severity: "critical", description: "GitHub personal access token.", category: "Dev", fixSuggestion: "Revoke at GitHub → Settings → Developer settings → Personal access tokens. Use fine-grained tokens with repo-specific access." },
  { name: "GitHub Actions Token", pattern: /^ghs_[a-zA-Z0-9]{36,}$/, severity: "critical", description: "GitHub Actions secret.", category: "Dev", fixSuggestion: "Regenerate in GitHub repo → Settings → Secrets → Actions. Use OIDC federation instead of long-lived secrets." },
  { name: "GitHub OAuth Token", pattern: /^gho_[a-zA-Z0-9]{36,}$/, severity: "critical", description: "GitHub OAuth token.", category: "Dev", fixSuggestion: "Revoke the OAuth app token at GitHub → Settings → Developer settings → OAuth Apps. Re-authorize with minimal scopes." },
  { name: "GitHub Refresh Token", pattern: /^ghr_[a-zA-Z0-9]{36,}$/, severity: "critical", description: "GitHub refresh token.", category: "Dev", fixSuggestion: "Revoke at GitHub → Settings → Developer settings → OAuth Apps. Implement token rotation in your auth flow." },
  { name: "GitLab Token", pattern: /^glpat-[a-zA-Z0-9_-]{20,}$/, severity: "critical", description: "GitLab personal access token.", category: "Dev", fixSuggestion: "Revoke at GitLab → User Settings → Access Tokens. Use project-scoped tokens with minimal scopes." },
  { name: "Bitbucket App Password", pattern: /^[a-zA-Z0-9]{20}$/, severity: "medium", description: "Possible Bitbucket app password (short token).", category: "Dev", fixSuggestion: "Rotate at Bitbucket → Personal Settings → App passwords. Use OAuth 2.0 for integrations." },
  { name: "npm Token", pattern: /^npm_[A-Za-z0-9]{36}$/, severity: "critical", description: "npm access token. Revoke at npmjs.com/settings/tokens.", category: "Dev", fixSuggestion: "Revoke at npmjs.com → Access Tokens. Use granular tokens scoped to specific packages." },
  { name: "PyPI Token", pattern: /^pypi-[A-Za-z0-9_-]{50,}$/, severity: "critical", description: "PyPI API token. Revoke at pypi.org/manage/account/token-settings.", category: "Dev", fixSuggestion: "Revoke at PyPI → Account settings → API tokens. Scope tokens to specific projects only." },
  { name: "npm Automation Token", pattern: /^npm_[a-zA-Z0-9]{36}$/, severity: "critical", description: "npm automation token.", category: "Dev", fixSuggestion: "Revoke at npmjs.com → Access Tokens. Use CI/CD OIDC tokens where supported." },

  // Communication
  { name: "Slack Webhook", pattern: /^https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9/]+$/, severity: "high", description: "Slack webhook URL. Can post messages to channels.", category: "Comm", fixSuggestion: "Regenerate webhook in Slack → Apps → Incoming Webhooks. Use Slack Bolt for better security." },
  { name: "Slack Bot Token", pattern: /^xoxb-[0-9]{11,}-[A-Za-z0-9-]{24,}$/, severity: "critical", description: "Slack bot token. Revoke via Slack admin.", category: "Comm", fixSuggestion: "Revoke at Slack admin → Manage apps → Your app → OAuth & Permissions. Reinstall with minimal scopes." },
  { name: "Slack User Token", pattern: /^xoxp-[0-9]{11,}-[A-Za-z0-9-]{24,}$/, severity: "critical", description: "Slack user token. Revoke via Slack admin.", category: "Comm", fixSuggestion: "Revoke user token. Migrate to bot tokens or OAuth 2.0 user tokens." },
  { name: "Discord Webhook", pattern: /^https:\/\/discord\.com\/api\/webhooks\/[0-9]+\/[A-Za-z0-9_-]+$/, severity: "high", description: "Discord webhook. Can send messages.", category: "Comm", fixSuggestion: "Regenerate webhook in Discord server settings → Integrations → Webhooks." },
  { name: "Discord Bot Token", pattern: /^N[A-Za-z0-9_-]{23,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{27,}$/, severity: "critical", description: "Discord bot token. Regenerate in Discord Developer Portal.", category: "Comm", fixSuggestion: "Regenerate at Discord Developer Portal → Bot → Reset Token. Consider using Discord.js interactions." },
  { name: "Telegram Bot Token", pattern: /^[0-9]{8,10}:[A-Za-z0-9_-]{35}$/, severity: "high", description: "Telegram bot token. Revoke via @BotFather.", category: "Comm", fixSuggestion: "Revoke via @BotFather → /revoke command. Use environment-specific tokens." },
  { name: "Twilio Account SID", pattern: /^AC[a-f0-9]{32}$/, severity: "high", description: "Twilio Account SID. Pair with API key for full access.", category: "Comm", fixSuggestion: "Not sensitive alone, but protect the paired API key. Use Twilio environment variables." },
  { name: "Twilio API Key", pattern: /^SK[a-f0-9]{32}$/, severity: "critical", description: "Twilio API key. Revoke in Twilio Console.", category: "Comm", fixSuggestion: "Revoke at Twilio Console → API keys. Use account-level credentials sparingly." },

  // Email / Mail
  { name: "SendGrid API Key", pattern: /^SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}$/, severity: "critical", description: "SendGrid API key. Revoke at sendgrid.com.", category: "Email", fixSuggestion: "Revoke at SendGrid → Settings → API Keys. Create a new key with restricted permissions." },
  { name: "Mailgun API Key", pattern: /^key-[0-9a-zA-Z]{32}$/, severity: "high", description: "Mailgun API key. Rotate in Mailgun dashboard.", category: "Email", fixSuggestion: "Rotate at Mailgun → Settings → API keys. Use domain-scoped keys." },
  { name: "Mailgun Public Key", pattern: /^pubkey-[0-9a-zA-Z]{32}$/, severity: "medium", description: "Mailgun public key. Low risk but keep private.", category: "Email", fixSuggestion: "Low risk but rotate for defense-in-depth. Keep in environment variables only." },

  // AI / ML
  { name: "OpenAI API Key", pattern: /^sk-[A-Za-z0-9]{48,}$/, severity: "critical", description: "OpenAI API key. Rotate at platform.openai.com.", category: "AI", fixSuggestion: "Revoke at platform.openai.com → API keys. Use organization-scoped keys with spending limits." },
  { name: "Anthropic API Key", pattern: /^sk-ant-[A-Za-z0-9_-]{40,}$/, severity: "critical", description: "Anthropic Claude API key.", category: "AI", fixSuggestion: "Revoke at console.anthropic.com → API Keys. Use project-scoped keys." },
  { name: "Cohere API Key", pattern: /^[A-Za-z0-9]{40}$/, severity: "medium", description: "Possible Cohere API key (40-char alphanumeric).", category: "AI", fixSuggestion: "Rotate at dashboard.cohere.com → API keys. Verify this is actually a Cohere key." },
  { name: "Hugging Face Token", pattern: /^hf_[A-Za-z0-9]{34,}$/, severity: "critical", description: "Hugging Face API token.", category: "AI", fixSuggestion: "Revoke at huggingface.co/settings/tokens. Use fine-grained tokens with model-specific access." },
  { name: "Replicate API Token", pattern: /^r8_[A-Za-z0-9]{40}$/, severity: "critical", description: "Replicate API token.", category: "AI", fixSuggestion: "Revoke at replicate.com/account/api-tokens. Use per-project tokens." },
  { name: "Vercel Token", pattern: /^vrsl_[A-Za-z0-9]{24,}$/, severity: "critical", description: "Vercel access token.", category: "AI", fixSuggestion: "Revoke at vercel.com/account/tokens. Use team-scoped tokens for CI/CD." },

  // General secrets
  { name: "JWT Token", pattern: /^eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}$/, severity: "high", description: "JSON Web Token. May contain sensitive claims.", category: "General", fixSuggestion: "Do not store JWTs in .env files. Generate them at runtime or use short-lived tokens. Rotate the signing secret." },
  { name: "Private Key", pattern: /^-----BEGIN (RSA |EC |DSA |ED25519 )?PRIVATE KEY-----$/m, severity: "critical", description: "Private key. Never share. Regenerate immediately.", category: "General", fixSuggestion: "Remove from .env immediately. Store in a secrets manager (Vault, AWS SSM). Regenerate the key pair." },
  { name: "PGP Private Key", pattern: /^-----BEGIN PGP PRIVATE KEY BLOCK-----$/m, severity: "critical", description: "PGP private key block.", category: "General", fixSuggestion: "Remove from .env. Use gpg-agent or a secrets manager. Regenerate the key." },
  { name: "SSH Private Key", pattern: /^-----BEGIN OPENSSH PRIVATE KEY-----$/m, severity: "critical", description: "SSH private key. Regenerate and update authorized_keys.", category: "General", fixSuggestion: "Remove from .env. Use ssh-agent. Regenerate with ssh-keygen and update all authorized_keys." },
  { name: "Database Connection URL", pattern: /^(postgres|mysql|mongodb|redis|amqp|rabbitmq):\/\/[^@\s]+@[^\/\s]+/, severity: "critical", description: "Database connection string with credentials.", category: "General", fixSuggestion: "Use a secrets manager. For production, use IAM auth or short-lived credentials. Rotate the DB password." },
  { name: "URL with Embedded Password", pattern: /^https?:\/\/[^:]+:[^@]+@/, severity: "critical", description: "URL with embedded credentials in plain text.", category: "General", fixSuggestion: "Remove password from URL. Use environment variables for credentials separately. Rotate the password." },
  { name: "Base64 Encoded Secret (long)", pattern: /^[A-Za-z0-9+/]{100,}={0,2}$/, severity: "medium", description: "Long base64 string. Could be an encoded secret.", category: "General", fixSuggestion: "Verify if this contains a secret. If so, move to a secrets manager and rotate." },
  { name: "Hex Encoded Secret (long)", pattern: /^[0-9a-fA-F]{64,}$/, severity: "medium", description: "Long hex string. Could be a hash or encoded secret.", category: "General", fixSuggestion: "Verify if this is a cryptographic key. If so, rotate and store in a secrets manager." },
  { name: "Bearer Token", pattern: /^Bearer\s+[A-Za-z0-9._-]{20,}$/, severity: "high", description: "Bearer authentication token.", category: "General", fixSuggestion: "Do not store tokens in .env files. Generate at runtime using OAuth flow. Implement token refresh." },
  { name: "Basic Auth Header", pattern: /^Basic\s+[A-Za-z0-9+/=]{20,}$/, severity: "high", description: "HTTP Basic Auth header with encoded credentials.", category: "General", fixSuggestion: "Remove from .env. Store username/password separately in environment variables. Rotate the password." },

  // Informational
  { name: "IP Address", pattern: /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/, severity: "low", description: "IP address. Usually low risk but could be internal.", category: "Info", fixSuggestion: "Verify if this is an internal IP that should not be public. Use environment variables for runtime resolution." },
  { name: "Email Address", pattern: /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/, severity: "low", description: "Email address. Consider if it should be public.", category: "Info", fixSuggestion: "Consider if this email should be public. Use a no-reply address for service accounts." },
  { name: "Phone Number", pattern: /^\+?[1-9]\d{6,14}$/, severity: "low", description: "Phone number in E.164 format.", category: "Info", fixSuggestion: "Consider if this phone number should be public. Use a service number instead of personal." },
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
  const [entries, setEntries] = useState<FileEntry[]>([]);
  const [dragOver, setDragOver] = useState(false);
  const [fileName, setFileName] = useState<string | null>(null);
  const [bulkResults, setBulkResults] = useState<BulkFileResult[]>([]);
  const [bulkMode, setBulkMode] = useState(false);
  const fileRef = useRef<HTMLInputElement>(null);
  const bulkDirRef = useRef<HTMLInputElement>(null);

  const parseEnv = useCallback((text: string, name?: string): FileEntry[] => {
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
    return parsed;
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
      reader.onload = () => { parseEnv(reader.result as string, file.name); };
      reader.readAsText(file);
    },
    [parseEnv]
  );

  // Feature 1: Bulk scan - handle directory selection
  const onBulkDirPick = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      const files = e.target.files;
      if (!files || files.length === 0) return;
      const results: BulkFileResult[] = [];
      let pending = files.length;
      for (const file of Array.from(files)) {
        const reader = new FileReader();
        reader.onload = () => {
          const text = reader.result as string;
          const lines = text.split("\n").filter((l) => l.trim() && !l.trim().startsWith("#"));
          const parsed: FileEntry[] = lines
            .map((line) => {
              const eq = line.indexOf("=");
 if (eq === -1) return null;
              const key = line.slice(0, eq).trim();
              if (!key || key.includes(" ")) return null;
              const raw = line.slice(eq + 1);
              let val = raw.trim();
              if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
                val = val.slice(1, -1);
              }
              return { key, value: val, results: analyzeKey(val) };
            })
            .filter(Boolean) as FileEntry[];
          results.push({ name: file.name, entries: parsed });
          pending--;
          if (pending === 0) {
            results.sort((a, b) => a.name.localeCompare(b.name));
            setBulkResults(results);
            setBulkMode(true);
            setEntries([]);
            setFileName(null);
          }
        };
        reader.readAsText(file);
      }
    },
    []
  );

  // Feature 3: Export as JSON
  const exportJSON = useCallback(() => {
    const data = bulkMode ? bulkResults : [{ name: fileName || ".env", entries }];
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "envfile-report.json";
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }, [bulkMode, bulkResults, entries, fileName]);

  // Feature 3: Export as HTML
  const exportHTML = useCallback(() => {
    const data = bulkMode ? bulkResults : [{ name: fileName || ".env", entries }];
    let totalCritical = 0, totalHigh = 0, totalMedium = 0, totalLow = 0, totalClean = 0;
    data.forEach((f) => {
      f.entries.forEach((e) => {
        if (e.results.length === 0) { totalClean++; return; }
        e.results.forEach((r) => {
          if (r.severity === "critical") totalCritical++;
          else if (r.severity === "high") totalHigh++;
          else if (r.severity === "medium") totalMedium++;
          else totalLow++;
        });
      });
    });
    const severityColors: Record<string, string> = { critical: "#dc2626", high: "#ea580c", medium: "#ca8a04", low: "#16a34a" };
    let html = `<!DOCTYPE html><html><head><meta charset="utf-8"><title>envfile.fyi Report</title>
<style>body{font-family:system-ui,sans-serif;max-width:900px;margin:40px auto;padding:20px;color:#1a1a1a}
h1{display:flex;align-items:center;gap:10px}.summary{display:flex;gap:12px;margin:16px 0;flex-wrap:wrap}
.badge{padding:6px 14px;border-radius:20px;font-size:13px;font-weight:700}
.file-section{margin:24px 0;border:1px solid #e5e7eb;border-radius:12px;overflow:hidden}
.file-header{background:#f9fafb;padding:12px 16px;font-weight:700;border-bottom:1px solid #e5e7eb}
.entry{padding:10px 16px;border-bottom:1px solid #f3f4f6}.entry:last-child{border-bottom:none}
.fix{margin:6px 0 0 16px;padding:8px 12px;background:#f0fdf4;border-radius:6px;font-size:12px;color:#166534;border:1px solid #bbf7d0}
code{background:#f3f4f6;padding:2px 6px;border-radius:4px;font-size:13px}</style></head><body>
<h1>🔐 envfile.fyi Report</h1>
<p style="color:#666">Generated by envfile.fyi — 100% client-side analysis</p>
<div class="summary">`;
    if (totalCritical) html += `<span class="badge" style="background:#fef2f2;color:#dc2626;border:1px solid #fca5a5">🔴 ${totalCritical} critical</span>`;
    if (totalHigh) html += `<span class="badge" style="background:#fff7ed;color:#ea580c;border:1px solid #fdba74">🟠 ${totalHigh} high</span>`;
    if (totalMedium) html += `<span class="badge" style="background:#fefce8;color:#ca8a04;border:1px solid #fde047">🟡 ${totalMedium} medium</span>`;
    if (totalLow) html += `<span class="badge" style="background:#f0fdf4;color:#16a34a;border:1px solid #86efac">🟢 ${totalLow} low</span>`;
    if (totalClean) html += `<span class="badge" style="background:#f0fdf4;color:#16a34a;border:1px solid #86efac">✅ ${totalClean} clean</span>`;
    html += `</div>`;
    data.forEach((f) => {
      const flagged = f.entries.filter((e) => e.results.length > 0).length;
      html += `<div class="file-section"><div class="file-header">📄 ${f.name} — ${f.entries.length} keys, ${flagged} flagged</div>`;
      f.entries.forEach((e) => {
        const color = e.results.length > 0 ? severityColors[e.results[0].severity] : "#16a34a";
        html += `<div class="entry"><code>${e.key}</code> <span style="color:#aaa">→</span> <code style="color:#666">${e.value.length > 60 ? e.value.slice(0, 60) + "…" : e.value || "(empty)"}</code>`;
        e.results.forEach((r) => {
          html += `<div style="margin-top:4px;font-size:12px;color:${severityColors[r.severity]}"><strong>${r.name}</strong> — ${r.description}</div>`;
          html += `<div class="fix">💡 <strong>Fix:</strong> ${r.fixSuggestion}</div>`;
        });
        html += `</div>`;
      });
      html += `</div>`;
    });
    html += `</body></html>`;
    const blob = new Blob([html], { type: "text/html" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "envfile-report.html";
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }, [bulkMode, bulkResults, entries, fileName]);

  const generateExample = () => {
    const source = bulkMode ? bulkResults.flatMap((f) => f.entries) : entries;
    const lines = source.map((e) => {
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

  const hasData = bulkMode ? bulkResults.length > 0 : entries.length > 0;
  const allEntries = bulkMode ? bulkResults.flatMap((f) => f.entries) : entries;
  const critical = allEntries.filter((e) => e.results.some((r) => r.severity === "critical")).length;
  const high = allEntries.filter((e) => e.results.some((r) => r.severity === "high")).length;
  const medium = allEntries.filter((e) => e.results.some((r) => r.severity === "medium")).length;
  const low = allEntries.filter((e) => e.results.some((r) => r.severity === "low")).length;
  const clean = allEntries.filter((e) => e.results.length === 0).length;
  const flagged = allEntries.filter((e) => e.results.length > 0).length;

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
        Drag a <code style={{ background: "#f3f4f6", padding: "2px 6px", borderRadius: 4 }}>.env</code> file to audit it, or <strong>bulk scan</strong> an entire folder.
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
          border: `2px dashed ${dragOver ? "#2563eb" : hasData ? (worst && SEVERITY_COLORS[worst].border) : "#d1d5db"}`,
          borderRadius: 16,
          padding: hasData ? "20px 24px" : 56,
          textAlign: "center",
          cursor: "pointer",
          background: dragOver ? "#eff6ff" : hasData ? "#fafafa" : "#fff",
          marginBottom: 28,
          transition: "all 0.2s ease",
          position: "relative",
        }}
      >
        <input ref={fileRef} type="file" accept=".env,.txt,.env.*" onChange={onFilePick} style={{ display: "none" }} />
        {/* @ts-expect-error webkitdirectory is non-standard but supported by browsers */}
        <input ref={bulkDirRef} type="file" webkitdirectory="" directory="" multiple accept=".env,.env.*,.txt" onChange={onBulkDirPick} style={{ display: "none" }} />

        {!hasData ? (
          <>
            <div style={{ fontSize: 48, marginBottom: 12 }}>📄</div>
            <p style={{ color: "#6b7280", fontSize: 16, margin: 0 }}>
              Drop <strong>.env</strong> file here, or click to browse
            </p>
            <p style={{ color: "#9ca3af", fontSize: 13, margin: "8px 0 0" }}>
              Supports .env, .env.local, .env.production, etc.
            </p>
            <button
              onClick={(e) => { e.stopPropagation(); bulkDirRef.current?.click(); }}
              style={{ marginTop: 16, padding: "10px 20px", background: "#7c3aed", color: "#fff", border: "none", borderRadius: 8, cursor: "pointer", fontSize: 14, fontWeight: 600, display: "inline-flex", alignItems: "center", gap: 6 }}
            >
              📂 Bulk Scan Folder
            </button>
          </>
        ) : (
          <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 12 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <span style={{ fontSize: 20 }}>📋</span>
              <span style={{ fontSize: 16, fontWeight: 600 }}>
                {bulkMode ? `${bulkResults.length} files scanned` : fileName && (
                  <span style={{ color: "#374151", marginRight: 8 }}>{fileName}</span>
                )}
                {bulkMode ? `— ${allEntries.length} keys total` : `${entries.length} keys scanned`}
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

            <div style={{ display: "flex", gap: 8, marginTop: 4, flexWrap: "wrap", justifyContent: "center" }}>
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
                  setBulkResults([]);
                  setBulkMode(false);
                  if (fileRef.current) fileRef.current.value = "";
                   if (bulkDirRef.current) bulkDirRef.current.value = "";
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

      {/* Export buttons */}
      {hasData && (
        <div style={{ display: "flex", gap: 8, marginBottom: 20, flexWrap: "wrap" }}>
          <button onClick={(e) => { e.stopPropagation(); exportJSON(); }} style={{ padding: "8px 16px", background: "#059669", color: "#fff", border: "none", borderRadius: 8, cursor: "pointer", fontSize: 13, fontWeight: 600 }}>
            📄 Export JSON
          </button>
          <button onClick={(e) => { e.stopPropagation(); exportHTML(); }} style={{ padding: "8px 16px", background: "#0891b2", color: "#fff", border: "none", borderRadius: 8, cursor: "pointer", fontSize: 13, fontWeight: 600 }}>
            🌐 Export HTML
          </button>
          {!bulkMode && (
            <button onClick={(e) => { e.stopPropagation(); bulkDirRef.current?.click(); }} style={{ padding: "8px 16px", background: "#7c3aed", color: "#fff", border: "none", borderRadius: 8, cursor: "pointer", fontSize: 13, fontWeight: 600 }}>
              📂 Bulk Scan
            </button>
          )}
        </div>
      )}

      {/* Bulk results */}
      {bulkMode && bulkResults.map((f) => (
        <div key={f.name} style={{ marginBottom: 24, border: "1px solid #e5e7eb", borderRadius: 12, overflow: "hidden" }}>
          <div style={{ background: "#f9fafb", padding: "12px 16px", borderBottom: "1px solid #e5e7eb", fontWeight: 700, fontSize: 14 }}>
            📄 {f.name} — {f.entries.length} keys, {f.entries.filter((e) => e.results.length > 0).length} flagged
          </div>
          {f.entries.map((e) => {
            const topSeverity = e.results.length > 0 ? e.results.reduce((acc, r) => (SEVERITY_ORDER[r.severity] < SEVERITY_ORDER[acc] ? r.severity : acc), "low" as Severity) : null;
            const colors = topSeverity ? SEVERITY_COLORS[topSeverity] : null;
            return (
              <div key={e.key} style={{ padding: "10px 16px", borderBottom: "1px solid #f3f4f6", background: e.results.length > 0 ? colors?.bg : "#fff" }}>
                <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                  <code style={{ fontWeight: 700, fontSize: 13, color: e.results.length > 0 ? colors?.fg : "#374151" }}>{e.key}</code>
                  <span style={{ color: "#d1d5db" }}>→</span>
                  <code style={{ fontSize: 12, color: "#6b7280", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", flex: 1 }}>{e.value.length > 60 ? e.value.slice(0, 60) + "…" : e.value || "(empty)"}</code>
                  {e.results.length > 0 && <span style={{ fontSize: 11, fontWeight: 700, color: colors?.fg }}>{SEVERITY_LABELS[topSeverity!].split(" ").pop()}</span>}
                </div>
                {e.results.map((r, i) => (
                  <div key={i} style={{ marginTop: 6, paddingLeft: 12 }}>
                    <div style={{ fontSize: 12, color: SEVERITY_COLORS[r.severity].fg }}><strong>{r.name}</strong> — {r.description}</div>
                    <div style={{ marginTop: 3, padding: "6px 10px", borderRadius: 6, fontSize: 12, background: "#f0fdf4", color: "#166534", border: "1px solid #bbf7d0" }}>💡 <strong>Fix:</strong> {r.fixSuggestion}</div>
                  </div>
                ))}
              </div>
            );
          })}
        </div>
      ))}

      {/* Single file entries list */}
      {!bulkMode && entries.map((e) => {
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
                  padding: "8px 10px",
                  borderRadius: 6,
                  fontSize: 12,
                  background: SEVERITY_COLORS[r.severity].bg,
                  color: SEVERITY_COLORS[r.severity].fg,
                  border: `1px solid ${SEVERITY_COLORS[r.severity].border}`,
                  fontWeight: r.severity === "critical" ? 700 : 500,
                }}
              >
                <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                  <span style={{ fontSize: 10 }}>{SEVERITY_LABELS[r.severity].split(" ")[0]}</span>
                  <strong>{r.name}</strong>
                  <span style={{ opacity: 0.8 }}>— {r.description}</span>
                </div>
                <div style={{ marginTop: 4, padding: "6px 10px", borderRadius: 6, fontSize: 11, background: "#f0fdf4", color: "#166534", border: "1px solid #bbf7d0" }}>💡 <strong>Fix:</strong> {r.fixSuggestion}</div>
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
