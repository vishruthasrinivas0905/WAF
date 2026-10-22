import React, { useCallback, useEffect, useState } from "react";
import { Activity, AlertTriangle, LockKeyhole, Send, Shield } from "lucide-react";
import { SecurityEvent, WafMetrics } from "./waf/types.ts";

const emptyMetrics: WafMetrics = {
  totalRequests: 0,
  allowed: 0,
  monitored: 0,
  blocked: 0,
  totalRuleMatches: 0,
  p50LatencyMs: 0,
  p95LatencyMs: 0,
  p99LatencyMs: 0,
  categoryCounts: { SQLI: 0, XSS: 0, RCE: 0, TRAVERSAL: 0, SCANNER: 0 },
};

export default function App() {
  const [adminToken, setAdminToken] = useState("");
  const [adminError, setAdminError] = useState("");
  const [mode, setMode] = useState<"ENFORCING" | "MONITORING">("ENFORCING");
  const [method, setMethod] = useState("GET");
  const [target, setTarget] = useState("/api/v1/products?category=electronics&page=1");
  const [body, setBody] = useState("");
  const [event, setEvent] = useState<SecurityEvent | null>(null);
  const [gatewayResult, setGatewayResult] = useState<any>(null);
  const [metrics, setMetrics] = useState<WafMetrics>(emptyMetrics);
  const [recentEvents, setRecentEvents] = useState<SecurityEvent[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const apiFetch = useCallback((url: string, init: RequestInit = {}) => {
    const headers = new Headers(init.headers);
    if (adminToken) headers.set("Authorization", `Bearer ${adminToken}`);
    return fetch(url, { ...init, headers });
  }, [adminToken]);

  const refreshTelemetry = useCallback(async () => {
    try {
      const [metricsResponse, eventsResponse, modeResponse] = await Promise.all([
        apiFetch("/api/waf/metrics"),
        apiFetch("/api/waf/events"),
        apiFetch("/api/waf/policy/mode"),
      ]);
      if (metricsResponse.status === 401 || eventsResponse.status === 401 || modeResponse.status === 401) {
        setAdminError("Management API key required or invalid.");
        return;
      }
      if (metricsResponse.ok) setMetrics(await metricsResponse.json());
      if (eventsResponse.ok) setRecentEvents(await eventsResponse.json());
      if (modeResponse.ok) setMode((await modeResponse.json()).mode);
      setAdminError("");
    } catch {
      setError("Cannot reach the local WAF service yet.");
    }
  }, [apiFetch]);

  useEffect(() => {
    refreshTelemetry();
    const interval = setInterval(refreshTelemetry, 4000);
    return () => clearInterval(interval);
  }, [refreshTelemetry]);

  const changeMode = async (nextMode: "ENFORCING" | "MONITORING") => {
    try {
      const response = await apiFetch("/api/waf/policy/mode", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ mode: nextMode }),
      });
      const result = await response.json();
      if (!response.ok) throw new Error(result.error || "Mode update failed.");
      setMode(nextMode);
      setAdminError("");
    } catch (err) {
      setAdminError(err instanceof Error ? err.message : "Mode update failed.");
    }
  };

  const inspectAndSend = async (submitEvent: React.FormEvent) => {
    submitEvent.preventDefault();
    setBusy(true);
    setError("");
    setGatewayResult(null);
    setEvent(null);
    try {
      const rawRequest = `${method} ${target} HTTP/1.1\r\nHost: gateway.local\r\nUser-Agent: AppAware-WAF-Demo\r\n${body ? "Content-Type: application/json\r\n" : ""}\r\n${body}`;
      const inspectResponse = await apiFetch("/api/waf/inspect", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ request: rawRequest }),
      });
      const inspectData = await inspectResponse.json();
      if (!inspectResponse.ok) {
        if (inspectResponse.status === 401) setAdminError("Management API key required or invalid.");
        throw new Error(inspectData.error || "Inspection failed.");
      }
      setEvent(inspectData);

      const proxyTarget = target.startsWith("/") ? target : `/${target}`;
      const proxyResponse = await fetch(`/proxy${proxyTarget}`, {
        method,
        headers: body ? { "Content-Type": "application/json" } : undefined,
        body: body && !["GET", "HEAD"].includes(method) ? body : undefined,
      });
      const responseText = await proxyResponse.text();
      let responseData: unknown = responseText;
      try { responseData = JSON.parse(responseText); } catch { /* Plain text or HTML upstream response. */ }
      setGatewayResult({
        status: proxyResponse.status,
        mode: proxyResponse.headers.get("X-WAF-Upstream-Mode") || "unknown",
        decision: proxyResponse.headers.get("X-WAF-Decision"),
        body: responseData,
      });
      await refreshTelemetry();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Request failed.");
    } finally {
      setBusy(false);
    }
  };

  const decisionColor = (decision: string) => decision === "BLOCK" ? "text-rose-300" : decision === "MONITOR" ? "text-amber-300" : "text-emerald-300";

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100">
      <header className="border-b border-slate-800 bg-slate-900/80">
        <div className="max-w-7xl mx-auto px-4 py-4 flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="rounded-lg bg-indigo-600 p-2"><Shield className="w-5 h-5" /></div>
            <div>
              <h1 className="font-bold">AppAware-WAF</h1>
              <p className="text-xs text-slate-400">Request inspection and configured-upstream demo</p>
            </div>
          </div>
          <label className="flex items-center gap-2 text-xs text-slate-300">
            <LockKeyhole className="w-4 h-4" />
            <span>Management API key</span>
            <input type="password" autoComplete="off" value={adminToken} onChange={(e) => setAdminToken(e.target.value)} placeholder="If configured" className="w-56 rounded border border-slate-700 bg-slate-950 px-2.5 py-2" />
          </label>
        </div>
      </header>

      <main className="max-w-7xl mx-auto p-4 sm:p-6 space-y-5">
        <section className="rounded-xl border border-amber-500/30 bg-amber-500/10 p-4 flex gap-3 text-sm text-amber-100">
          <AlertTriangle className="w-5 h-5 shrink-0 text-amber-300" />
          <div><strong>Research prototype:</strong> The bundled score is a handcrafted heuristic, not a trained Transformer. No research dataset or model checkpoint is included. Previous dataset-scale figures were not reproducible from this checkout and are not shown as results.</div>
        </section>

        {adminError && <p className="rounded-lg border border-amber-500/30 bg-slate-900 p-3 text-sm text-amber-200">{adminError}</p>}
        {error && <p className="rounded-lg border border-rose-500/30 bg-slate-900 p-3 text-sm text-rose-200">{error}</p>}

        <div className="grid gap-5 lg:grid-cols-5">
          <form onSubmit={inspectAndSend} className="lg:col-span-3 rounded-xl border border-slate-800 bg-slate-900 p-5 space-y-4">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <h2 className="font-semibold">Inspect a request</h2>
              <div className="flex gap-1 rounded-lg bg-slate-950 p-1">
                {(["ENFORCING", "MONITORING"] as const).map((item) => (
                  <button key={item} type="button" onClick={() => changeMode(item)} className={`rounded px-3 py-1.5 text-xs ${mode === item ? "bg-indigo-600 text-white" : "text-slate-400"}`}>{item}</button>
                ))}
              </div>
            </div>
            <div className="grid gap-3 sm:grid-cols-[130px_1fr]">
              <label className="text-xs text-slate-400">Method
                <select value={method} onChange={(e) => setMethod(e.target.value)} className="mt-1 w-full rounded border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100">
                  {["GET", "POST", "PUT", "DELETE", "PATCH"].map((verb) => <option key={verb}>{verb}</option>)}
                </select>
              </label>
              <label className="text-xs text-slate-400">Path and query
                <input required value={target} onChange={(e) => setTarget(e.target.value)} className="mt-1 w-full rounded border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100" />
              </label>
            </div>
            <label className="block text-xs text-slate-400">Optional request body
              <textarea value={body} onChange={(e) => setBody(e.target.value)} rows={5} placeholder='{"comment":"hello"}' className="mt-1 w-full rounded border border-slate-700 bg-slate-950 px-3 py-2 font-mono text-sm text-slate-100" />
            </label>
            <button disabled={busy} className="inline-flex items-center gap-2 rounded-lg bg-indigo-600 px-4 py-2.5 text-sm font-medium hover:bg-indigo-500 disabled:opacity-50">
              <Send className="w-4 h-4" />{busy ? "Inspecting…" : "Inspect and send through gateway"}
            </button>
            <p className="text-xs text-slate-500">The dashboard sends one inspection request and then sends the request through `/proxy/*`; use a test target you control.</p>
          </form>

          <section className="lg:col-span-2 rounded-xl border border-slate-800 bg-slate-900 p-5">
            <h2 className="mb-4 flex items-center gap-2 font-semibold"><Activity className="w-4 h-4 text-cyan-300" />Runtime telemetry</h2>
            <div className="grid grid-cols-2 gap-3 text-sm">
              <Metric label="Requests" value={metrics.totalRequests} />
              <Metric label="Blocked" value={metrics.blocked} />
              <Metric label="Allowed" value={metrics.allowed} />
              <Metric label="Monitored" value={metrics.monitored} />
              <Metric label="P50 inspection" value={`${metrics.p50LatencyMs.toFixed(2)} ms`} />
              <Metric label="P95 inspection" value={`${metrics.p95LatencyMs.toFixed(2)} ms`} />
            </div>
            <p className="mt-4 text-xs text-slate-500">In-memory counts for this process only; timings exclude client network and upstream latency.</p>
          </section>
        </div>

        {(event || gatewayResult) && (
          <div className="grid gap-5 lg:grid-cols-2">
            {event && <section className="rounded-xl border border-slate-800 bg-slate-900 p-5 space-y-3">
              <h2 className={`font-semibold ${decisionColor(event.decision)}`}>{event.decision} · risk {event.riskScore.toFixed(3)}</h2>
              <p className="text-sm text-slate-300">{event.decisionReason}</p>
              <div className="grid grid-cols-3 gap-2 text-xs">
                <Metric label="Rules" value={event.signals.deterministicScore.toFixed(3)} />
                <Metric label="Heuristic" value={event.signals.heuristicScore.toFixed(3)} />
                <Metric label="Profile" value={event.signals.profileScore.toFixed(3)} />
              </div>
              <div className="text-xs text-slate-400">Matched signatures: {event.matchedRules.length ? event.matchedRules.map((rule) => rule.ruleId).join(", ") : "none"}</div>
              {event.anomalyFlags.length > 0 && <div className="text-xs text-amber-300">Anomalies: {event.anomalyFlags.join(", ")}</div>}
            </section>}
            {gatewayResult && <section className="rounded-xl border border-slate-800 bg-slate-900 p-5 space-y-3">
              <h2 className="font-semibold">Gateway response · HTTP {gatewayResult.status}</h2>
              <p className="text-xs text-slate-400">Upstream mode: {gatewayResult.mode}</p>
              <pre className="max-h-72 overflow-auto rounded-lg bg-slate-950 p-3 text-xs">{JSON.stringify(gatewayResult.body, null, 2)}</pre>
            </section>}
          </div>
        )}

        <section className="rounded-xl border border-slate-800 bg-slate-900 p-5">
          <h2 className="mb-3 font-semibold">Recent security events</h2>
          {recentEvents.length === 0 ? <p className="text-sm text-slate-500">No events recorded in this process yet.</p> : (
            <div className="overflow-x-auto"><table className="w-full text-left text-xs">
              <thead className="text-slate-500"><tr><th className="py-2 pr-3">Time</th><th className="py-2 pr-3">Method</th><th className="py-2 pr-3">Path</th><th className="py-2 pr-3">Decision</th><th className="py-2">Risk</th></tr></thead>
              <tbody>{recentEvents.slice(0, 12).map((item) => <tr key={item.eventId} className="border-t border-slate-800"><td className="py-2 pr-3 text-slate-400">{new Date(item.timestamp).toLocaleTimeString()}</td><td className="py-2 pr-3">{item.method}</td><td className="py-2 pr-3 font-mono">{item.path}</td><td className={`py-2 pr-3 font-semibold ${decisionColor(item.decision)}`}>{item.decision}</td><td className="py-2">{item.riskScore.toFixed(3)}</td></tr>)}</tbody>
            </table></div>
          )}
        </section>

        <section className="grid gap-3 sm:grid-cols-3 text-xs text-slate-300">
          <StatusCard title="Scoring" body="Handcrafted lexical/entropy heuristic plus deterministic signatures; no neural checkpoint loaded." />
          <StatusCard title="Evaluation" body="Use scripts/evaluate_dataset.py with licensed data and grouped splits. The local smoke corpus is regression-only." />
          <StatusCard title="Gateway" body="UPSTREAM_URL enables a single-origin proxy. Without it, the response is marked mock-demo and is not forwarded." />
        </section>
      </main>
    </div>
  );
}

function Metric({ label, value }: { label: string; value: string | number }) {
  return <div className="rounded-lg border border-slate-800 bg-slate-950 p-3"><div className="text-[11px] text-slate-500">{label}</div><div className="mt-1 font-mono font-semibold text-slate-100">{value}</div></div>;
}

function StatusCard({ title, body }: { title: string; body: string }) {
  return <article className="rounded-xl border border-slate-800 bg-slate-900 p-4"><h3 className="mb-1 font-semibold text-white">{title}</h3><p className="leading-relaxed text-slate-400">{body}</p></article>;
}
