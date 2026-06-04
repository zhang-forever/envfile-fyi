import { useState, useCallback, useRef } from "react";

const KEY_PATTERNS: { name: string; pattern: RegExp; severity: "critical" | "high" | "medium" | "low"; description: string }[] = [
  { name: "AWS Access Key", pattern: /^AKIA[0-9A-Z]{16}$/, severity: "critical", description: "Grants AWS API access. Revoke immediately if exposed." },
  { name: "AWS Secret Key", pattern: /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[A-Za-z0-9/+]{40}$/, severity: "critical", description: "AWS secret access key. Rotate immediately." },
  { name: "Stripe Secret", pattern: /^sk_live_[0-9a-zA-Z]{24,}$/, severity: "critical", description: "Stripe production secret key." },
  { name: "Stripe Test", pattern: /^sk_test_[0-9a-zA-Z]{24,}$/, severity: "medium", description: "Stripe test key (not production, but keep private)." },
  { name: "GitHub Token", pattern: /^ghp_[a-zA-Z0-9]{36,}$/, severity: "critical", description: "GitHub personal access token." },
  { name: "GitHub Actions", pattern: /^ghs_[a-zA-Z0-9]{36,}$/, severity: "critical", description: "GitHub Actions secret." },
  { name: "Google API", pattern: /^AIza[0-9A-Za-z_-]{35}$/, severity: "high", description: "Google API key. Restrict by IP/referrer." },
  { name: "OpenAI Key", pattern: /^sk-[A-Za-z0-9]{32,}$/, severity: "critical", description: "OpenAI API key." },
  { name: "Anthropic Key", pattern: /^sk-ant-[A-Za-z0-9]{32,}$/, severity: "critical", description: "Anthropic Claude API key." },
  { name: "JWT Token", pattern: /^eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}$/, severity: "high", description: "JSON Web Token. May contain sensitive claims." },
  { name: "Private Key", pattern: /^-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----$/m, severity: "critical", description: "Private key. Never share." },
  { name: "Slack Webhook", pattern: /^https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9/]+$/, severity: "high", description: "Slack webhook URL. Can post messages." },
  { name: "Discord Webhook", pattern: /^https:\/\/discord\.com\/api\/webhooks\/[0-9]+\/[A-Za-z0-9_-]+$/, severity: "high", description: "Discord webhook. Can send messages." },
  { name: "Database URL", pattern: /^(postgres|mysql|mongodb|redis):\/\/[^@]+@/, severity: "critical", description: "Database connection string with credentials." },
  { name: "IP Address", pattern: /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/, severity: "medium", description: "IP address. Usually low risk but could be internal." },
  { name: "Email", pattern: /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/, severity: "low", description: "Email address." },
  { name: "URL with password", pattern: /^https?:\/\/[^:]+:[^@]+@/, severity: "critical", description: "URL with embedded credentials." },
];

function analyzeKey(value: string) {
  const results = [];
  for (const p of KEY_PATTERNS) {
    if (p.pattern.test(value)) {
      results.push({ ...p });
    }
  }
  return results;
}

export default function App() {
  const [entries, setEntries] = useState<{ key: string; value: string; results: ReturnType<typeof analyzeKey> }[]>([]);
  const [dragOver, setDragOver] = useState(false);
  const fileRef = useRef<HTMLInputElement>(null);

  const parseEnv = useCallback((text: string) => {
    const lines = text.split("\n").filter((l) => l.trim() && !l.trim().startsWith("#"));
    const parsed = lines.map((line) => {
      const eq = line.indexOf("=");
      if (eq === -1) return null;
      const key = line.slice(0, eq).trim();
      const val = line.slice(eq + 1).trim().replace(/^"(.*)"$/, "$1").replace(/^'(.*)'$/, "$1");
      return { key, value: val, results: analyzeKey(val) };
    }).filter(Boolean) as { key: string; value: string; results: ReturnType<typeof analyzeKey> }[];
    setEntries(parsed);
  }, []);

  const onDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(false);
    const file = e.dataTransfer.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => parseEnv(reader.result as string);
    reader.readAsText(file);
  }, [parseEnv]);

  const onFilePick = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => parseEnv(reader.result as string);
    reader.readAsText(file);
  }, [parseEnv]);

  const generateExample = () => {
    const lines = entries.map((e) => {
      if (e.results.length > 0) return `${e.key}=your_${e.key.toLowerCase()}_here`;
      return `${e.key}=${e.value}`;
    });
    const blob = new Blob([lines.join("\n")], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = ".env.example"; a.click();
    URL.revokeObjectURL(url);
  };

  const critical = entries.filter((e) => e.results.some((r) => r.severity === "critical")).length;
  const high = entries.filter((e) => e.results.some((r) => r.severity === "high")).length;
  const medium = entries.filter((e) => e.results.filter((r) => r.severity === "medium").length > 0).length;

  return (
    <div style={{ maxWidth: 800, margin: "0 auto", padding: 32, fontFamily: "system-ui" }}>
      <h1 style={{ fontSize: 24, fontWeight: 800 }}>envfile.fyi</h1>
      <p style={{ color: "#666", marginBottom: 24 }}>Drag a .env file. All analysis happens in your browser — nothing leaves your machine.</p>

      <div onDragOver={(e) => { e.preventDefault(); setDragOver(true); }} onDragLeave={() => setDragOver(false)} onDrop={onDrop}
        style={{ border: `2px dashed ${dragOver ? "#2563eb" : "#ccc"}`, borderRadius: 12, padding: 48, textAlign: "center", cursor: "pointer", background: dragOver ? "#eff6ff" : "#fff", marginBottom: 24 }}
        onClick={() => fileRef.current?.click()}>
        <input ref={fileRef} type="file" accept=".env,.txt" onChange={onFilePick} style={{ display: "none" }} />
        {entries.length === 0 ? (
          <p style={{ color: "#999" }}>Drop .env file here, or click to browse</p>
        ) : (
          <div>
            <p style={{ fontSize: 18, fontWeight: 600 }}>
              {entries.length} keys found
              {critical > 0 && <span style={{ color: "#ef4444", marginLeft: 12 }}>{critical} critical</span>}
              {high > 0 && <span style={{ color: "#f97316", marginLeft: 8 }}>{high} high</span>}
              {medium > 0 && <span style={{ color: "#eab308", marginLeft: 8 }}>{medium} medium</span>}
            </p>
            <button onClick={generateExample} style={{ marginTop: 12, padding: "8px 16px", background: "#2563eb", color: "#fff", border: "none", borderRadius: 6, cursor: "pointer", fontSize: 13 }}>
              Download .env.example
            </button>
          </div>
        )}
      </div>

      {entries.map((e) => (
        <div key={e.key} style={{ padding: "10px 0", borderBottom: "1px solid #f0f0f0" }}>
          <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
            <code style={{ fontWeight: 600, fontSize: 13 }}>{e.key}</code>
            <span>=</span>
            <code style={{ fontSize: 13, color: "#666", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", flex: 1 }}>
              {e.value.length > 60 ? e.value.slice(0, 60) + "..." : e.value}
            </code>
          </div>
          {e.results.map((r, i) => (
            <div key={i} style={{ marginTop: 4, padding: "4px 8px", borderRadius: 4, fontSize: 12, display: "inline-block", marginRight: 6,
              background: r.severity === "critical" ? "#fef2f2" : r.severity === "high" ? "#fff7ed" : r.severity === "medium" ? "#fefce8" : "#f0fdf4",
              color: r.severity === "critical" ? "#dc2626" : r.severity === "high" ? "#ea580c" : r.severity === "medium" ? "#ca8a04" : "#16a34a",
            }}>
              [{r.severity}] {r.name}: {r.description}
            </div>
          ))}
        </div>
      ))}
    </div>
  );
}
