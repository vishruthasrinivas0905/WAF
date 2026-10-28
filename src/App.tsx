import React, { useCallback, useEffect, useState } from "react";
import { Activity, AlertTriangle, ArrowDown, ArrowRight, BarChart3, CheckCircle2, Code2, Cpu, Database, FileText, Layers, Play, RefreshCw, Shield, ShieldAlert, ShieldCheck, Terminal, X } from "lucide-react";
import { SecurityEvent, WafMetrics } from "./waf/types.ts";

const emptyMetrics: WafMetrics = { totalRequests: 0, allowed: 0, monitored: 0, blocked: 0, totalRuleMatches: 0, p50LatencyMs: 0, p95LatencyMs: 0, p99LatencyMs: 0, categoryCounts: { SQLI: 0, XSS: 0, RCE: 0, TRAVERSAL: 0, SCANNER: 0 } };
type Tab = "gateway" | "evaluation" | "adaptation" | "robustness" | "dataset" | "research";
type DemoCase = { id: string; title: string; note: string; method: string; target: string; body: string; attack: boolean };
const demoCases: DemoCase[] = [
  { id: "safe", title: "Normal product search", note: "Ordinary query; expected to pass.", method: "GET", target: "/upstream/api/products?category=electronics&page=1", body: "", attack: false },
  { id: "sqli", title: "SQL injection attempt", note: "SQL tautology signature example.", method: "GET", target: "/upstream/api/products?id=1%20OR%201=1", body: "", attack: true },
  { id: "xss", title: "Script injection attempt", note: "HTML script signature example.", method: "POST", target: "/upstream/api/orders", body: JSON.stringify({ comment: "<script>alert(1)</script>" }, null, 2), attack: true },
  { id: "traversal", title: "Path traversal attempt", note: "Traversal signature example.", method: "GET", target: "/upstream/api/products?file=..%2F..%2Fetc%2Fpasswd", body: "", attack: true },
];
type GatewayResult = { status: number; decision: string; risk: number | null; mode: string; eventId: string; body: unknown; target: string; method: string };
type RuntimeHealth = { status: string; scoringEngine: string; upstreamConfigured: boolean };
type SmokeReport = { evidence_scope?: string; unique_samples?: number; timing_iterations_per_sample?: number; latency_ms?: { mean: number; p50: number; p95: number; p99: number }; metrics_by_lane?: Record<string, { accuracy: number; precision: number; recall: number; f1_score: number; fpr: number; fnr: number; n: number }>; error?: string; message?: string };

const tabs: { id: Tab; label: string; icon: typeof Shield }[] = [
  { id: "gateway", label: "Live Gateway", icon: Terminal }, { id: "evaluation", label: "Benchmark & Evaluation", icon: BarChart3 }, { id: "adaptation", label: "Few-Shot Adaptation", icon: Cpu }, { id: "robustness", label: "Robustness & Evasion", icon: Layers }, { id: "dataset", label: "Dataset & Provenance", icon: Database },
];

export default function App() {
  const [authenticated, setAuthenticated] = useState<boolean | null>(null);
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("");
  const [loginError, setLoginError] = useState("");
  const [loginBusy, setLoginBusy] = useState(false);
  const [activeTab, setActiveTab] = useState<Tab>("gateway");
  const [adminError, setAdminError] = useState("");
  const [mode, setMode] = useState<"ENFORCING" | "MONITORING">("ENFORCING");
  const [method, setMethod] = useState("GET");
  const [target, setTarget] = useState(demoCases[0].target);
  const [body, setBody] = useState("");
  const [selectedDemo, setSelectedDemo] = useState("safe");
  const [result, setResult] = useState<GatewayResult | null>(null);
  const [metrics, setMetrics] = useState<WafMetrics>(emptyMetrics);
  const [runtimeHealth, setRuntimeHealth] = useState<RuntimeHealth | null>(null);
  const [healthUnavailable, setHealthUnavailable] = useState(false);
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [budget, setBudget] = useState(0);
  const [adaptResult, setAdaptResult] = useState<{ status?: string; evidenceType?: string; adaptationBudget?: number; knownEndpointsCount?: number; endpoints?: string[]; error?: string } | null>(null);
  const [smokeReport, setSmokeReport] = useState<SmokeReport | null>(null);
  const [smokeBusy, setSmokeBusy] = useState(false);

  const apiFetch = useCallback((url: string, init: RequestInit = {}) => {
    const headers = new Headers(init.headers);
    return fetch(url, { ...init, headers, credentials: "same-origin" });
  }, []);

    useEffect(() => {
    fetch("/api/auth/me", { credentials: "same-origin" })
      .then((response) => response.json())
      .then((data) => {
        setAuthenticated(data.authenticated === true);
        if (data.username) setUsername(data.username);
      })
      .catch(() => {
        setAuthenticated(false);
        setLoginError("Unable to connect to the server.");
      });
  }, []);

  const handleLogin = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setLoginBusy(true);
    setLoginError("");

    try {
      const response = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "same-origin",
        body: JSON.stringify({ username, password }),
      });

      const data = await response.json();

      if (!response.ok) {
        setLoginError(data.error || "Login failed.");
        return;
      }

      setAuthenticated(true);
      setUsername(data.username || username);
      setPassword("");
    } catch {
      setLoginError("Unable to connect to the server.");
    } finally {
      setLoginBusy(false);
    }
  };

  const handleLogout = async () => {
    try {
      await fetch("/api/auth/logout", {
        method: "POST",
        credentials: "same-origin",
      });
    } finally {
      setAuthenticated(false);
      setPassword("");
      setEvents([]);
      setMetrics(emptyMetrics);
      setRuntimeHealth(null);
      setHealthUnavailable(false);
      setAdminError("");
    }
  };

  const refresh = useCallback(async () => {
    try {
      const [m, e, p] = await Promise.all([apiFetch("/api/waf/metrics"), apiFetch("/api/waf/events"), apiFetch("/api/waf/policy/mode")]);
      if ([m, e, p].some((r) => r.status === 401)) { setAdminError("Enter the configured management API key to use telemetry and policy controls."); return; }
      if (m.ok) setMetrics(await m.json()); if (e.ok) setEvents(await e.json());
      if (p.ok) setMode((await p.json()).mode); setAdminError(""); setError("");
      try {
        const health = await fetch("/healthz", { credentials: "same-origin" });
        if (!health.ok) throw new Error("Health check failed");
        setRuntimeHealth(await health.json());
        setHealthUnavailable(false);
      } catch { setRuntimeHealth(null); setHealthUnavailable(true); }
    } catch { setError("WAF service is not responding. Make sure the local server is running."); setRuntimeHealth(null); setHealthUnavailable(true); }
  }, [apiFetch]);

  const fetchSmokeReport = useCallback(async () => {
    try { const response = await apiFetch("/api/waf/benchmark/results"); if (response.ok) setSmokeReport(await response.json()); }
    catch { setSmokeReport({ message: "Smoke report is not available from the local service." }); }
  }, [apiFetch]);

  useEffect(() => {
    if (authenticated !== true) return;
    refresh();
    const timer = setInterval(refresh, 5000);
    return () => clearInterval(timer);
  }, [authenticated, refresh]);
  useEffect(() => {
    if (authenticated === true) fetchSmokeReport();
  }, [authenticated, fetchSmokeReport]);

  const changeMode = async (next: "ENFORCING" | "MONITORING") => {
    try {
      const r = await apiFetch("/api/waf/policy/mode", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ mode: next }) });
      const data = await r.json(); if (!r.ok) throw new Error(data.error || "Policy update failed."); setMode(next); setAdminError("");
    } catch (e) { setAdminError(e instanceof Error ? e.message : "Policy update failed."); }
  };

  const chooseDemo = (demo: DemoCase, openGateway = false) => { setSelectedDemo(demo.id); setMethod(demo.method); setTarget(demo.target); setBody(demo.body); setResult(null); setError(""); if (openGateway) setActiveTab("gateway"); };

  const sendRequest = async (event: React.FormEvent) => {
    event.preventDefault(); setBusy(true); setError(""); setResult(null);
    try {
      const requestTarget = target.trim();
      if (!requestTarget) throw new Error("Enter a path and query before sending the request.");
      const path = requestTarget.startsWith("/") ? requestTarget : `/${requestTarget}`;
      const headers = new Headers(); if (body.trim()) headers.set("Content-Type", "application/json");
      const response = await fetch(`/proxy${path}`, { method, headers, body: body.trim() && !["GET", "HEAD"].includes(method) ? body : undefined });
      const raw = await response.text(); let responseBody: unknown = raw; try { responseBody = JSON.parse(raw); } catch { /* upstream response may be text */ }
      const risk = response.headers.get("X-WAF-Risk-Score");
      setResult({ status: response.status, decision: response.headers.get("X-WAF-Decision") || "UNKNOWN", risk: risk === null ? null : Number(risk), mode: response.headers.get("X-WAF-Upstream-Mode") || "blocked before upstream", eventId: response.headers.get("X-WAF-Event-ID") || "—", body: responseBody, target: path, method });
      await refresh();
    } catch (e) { setError(e instanceof Error ? e.message : "Request could not be sent."); }
    finally { setBusy(false); }
  };

  const adapt = async (nextBudget: number) => {
    setBudget(nextBudget); setAdaptResult(null);
    try {
      const r = await apiFetch("/api/waf/adapt", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ budget: nextBudget }) });
      const data = await r.json(); if (!r.ok) throw new Error(data.error || "Profile update failed."); setAdaptResult(data);
    } catch (e) { setAdaptResult({ error: e instanceof Error ? e.message : "Profile update failed." }); }
  };

  const runSmoke = async () => {
    setSmokeBusy(true); setSmokeReport(null);
    try {
      const r = await apiFetch("/api/waf/benchmark/run", { method: "POST" }); const data = await r.json();
      if (!r.ok) throw new Error(data.error || "Smoke benchmark could not run."); setSmokeReport(data.data); await fetchSmokeReport();
    } catch (e) { setSmokeReport({ error: e instanceof Error ? e.message : "Smoke benchmark could not run." }); }
    finally { setSmokeBusy(false); }
  };

  const blockDetails = result?.body && typeof result.body === "object" ? result.body as { reason?: string; matchedRules?: Array<{ id: string; category: string; description: string }> } : null;

    if (authenticated === null) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-slate-950 text-white">
        Checking login...
      </div>
    );
  }

  if (!authenticated) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-slate-950 p-6 text-white">
        <form
          onSubmit={handleLogin}
          className="w-full max-w-md space-y-5 rounded-2xl border border-slate-700 bg-slate-900 p-8"
        >
          <div className="text-center">
            <h1 className="text-3xl font-bold">AppAware-WAF</h1>
            <p className="mt-2 text-sm text-slate-400">
              Sign in to access the security dashboard
            </p>
            <p className="mt-3 text-xs leading-5 text-slate-500">
              Use the dashboard username and password configured by your project administrator. These are separate from the WAF management API key.
            </p>
          </div>

          <div>
            <label className="mb-2 block text-sm">Username</label>
            <input
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              className="w-full rounded-lg border border-slate-700 bg-slate-950 p-3 text-white"
              autoComplete="username"
              required
            />
          </div>

          <div>
            <label className="mb-2 block text-sm">Password</label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full rounded-lg border border-slate-700 bg-slate-950 p-3 text-white"
              autoComplete="current-password"
              required
            />
          </div>

          {loginError && (
            <p className="text-sm text-red-400">{loginError}</p>
          )}

          <button
            type="submit"
            disabled={loginBusy}
            className="w-full rounded-lg bg-indigo-600 p-3 font-semibold hover:bg-indigo-500 disabled:opacity-50"
          >
            {loginBusy ? "Signing in..." : "Sign in"}
          </button>
        </form>
      </div>
    );
  }

  return <div className="min-h-screen bg-slate-950 text-slate-100">

    <header className="sticky top-0 z-20 border-b border-slate-800 bg-slate-900/95 backdrop-blur">
      <div className="mx-auto flex max-w-7xl flex-wrap items-center justify-between gap-4 px-4 py-3 sm:px-6">
        <div className="flex items-center gap-3"><div className="rounded-lg bg-indigo-600 p-2 text-white"><Shield className="h-5 w-5" /></div><div><div className="flex flex-wrap items-center gap-2"><span className="text-base font-bold tracking-tight">AppAware-WAF</span><span className="rounded border border-indigo-400/20 bg-indigo-500/10 px-2 py-0.5 text-[10px] font-medium uppercase text-indigo-300">Local Demo</span></div><p className="hidden text-xs text-slate-400 sm:block">Application-aware request inspection · deterministic signatures · heuristic scoring</p></div></div>
          <div className="flex flex-wrap items-center gap-3"><div className="hidden items-center gap-3 rounded-lg border border-slate-700 bg-slate-800/60 px-3 py-2 text-[11px] md:flex"><span className="text-slate-300"><Activity className="mr-1 inline h-3.5 w-3.5 text-cyan-300" />P50 <b className="font-mono text-cyan-200">{metrics.p50LatencyMs.toFixed(2)} ms</b></span><span className="text-emerald-300">Allowed {metrics.allowed}</span><span className="text-rose-300">Blocked {metrics.blocked}</span></div><div className="flex rounded-lg border border-slate-700 bg-slate-800 p-1">{(["ENFORCING", "MONITORING"] as const).map((item) => <button key={item} onClick={() => changeMode(item)} aria-pressed={mode === item} className={`rounded px-2.5 py-1.5 text-[10px] font-semibold ${mode === item ? item === "ENFORCING" ? "bg-rose-500/20 text-rose-200" : "bg-amber-500/20 text-amber-200" : "text-slate-400 hover:text-white"}`}>{item}</button>)}</div><button
  onClick={handleLogout}
  className="rounded-lg border border-slate-700 px-3 py-2 text-xs font-semibold text-slate-300 hover:bg-slate-800 hover:text-white"
>
  Log out
</button>
      </div>
    </div>
      <nav className="mx-auto flex max-w-7xl flex-wrap gap-x-1 border-t border-slate-800 px-3 sm:px-6" aria-label="Project pages">{tabs.map((tab) => { const Icon = tab.icon; return <button key={tab.id} onClick={() => setActiveTab(tab.id)} aria-current={activeTab === tab.id ? "page" : undefined} className={`flex shrink-0 items-center gap-2 border-b-2 px-3 py-3 text-xs font-medium transition ${activeTab === tab.id ? "border-indigo-400 bg-indigo-500/[0.06] text-indigo-300" : "border-transparent text-slate-400 hover:border-slate-600 hover:text-white"}`}><Icon className="h-4 w-4" />{tab.label}</button>; })}</nav>
    </header>

    <main className="mx-auto max-w-7xl space-y-6 p-4 sm:p-6 lg:p-8">
      {adminError && <Notice tone="amber">{adminError}</Notice>}{error && <Notice tone="rose">{error}</Notice>}

      {activeTab === "gateway" && <div className="space-y-5">
        <PageHeading eyebrow="Live Gateway Interceptor" title="Inspect a request, then see the gateway decision" text="The request is sent once through the local WAF gateway. The result includes the decision, matched rule, and mock or configured upstream response." />
        <div className="rounded-xl border border-indigo-400/20 bg-indigo-500/[0.06] p-4 text-xs leading-5 text-slate-300">
          <p className="font-semibold text-indigo-200">Sign-in and API key</p>
          <p className="mt-1">This dashboard uses your signed-in session for management controls, so you do not need to enter a separate API key here. <code>WAF_ADMIN_TOKEN</code> is configured on the server for direct management API clients and production setup. Keep it private.</p>
        </div>
        <div className="grid gap-5 lg:grid-cols-[1.15fr_0.85fr]">
          <form onSubmit={sendRequest} className="space-y-4 rounded-xl border border-slate-800 bg-slate-900/80 p-5">
            <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
  <div>
    <h2 className="text-lg font-semibold text-white">Test a Request</h2>
    <p className="mt-1 text-xs leading-5 text-slate-400">
      Choose an example, inspect it, and see how AppAware-WAF responds.
    </p>
  </div>

  <span className={`inline-flex w-fit items-center gap-2 rounded-full border px-3 py-1.5 text-xs font-medium ${healthUnavailable ? "border-rose-400/20 bg-rose-500/10 text-rose-200" : runtimeHealth?.upstreamConfigured ? "border-cyan-400/20 bg-cyan-500/10 text-cyan-200" : "border-emerald-400/20 bg-emerald-500/10 text-emerald-200"}`}>
    <span className={`h-2 w-2 rounded-full ${healthUnavailable ? "bg-rose-400" : runtimeHealth?.upstreamConfigured ? "bg-cyan-400" : "bg-emerald-400"}`}></span>
    {healthUnavailable ? "WAF unavailable" : runtimeHealth?.upstreamConfigured ? "Configured upstream" : runtimeHealth ? "Local mock mode" : "Checking service…"}
  </span>
</div>
           <div className="grid gap-3 sm:grid-cols-2">
  {demoCases.map((demo) => {
    const isSelected = selectedDemo === demo.id;

    return (
      <button
        type="button"
        key={demo.id}
        onClick={() => chooseDemo(demo)}
        aria-pressed={isSelected}
        className={`group rounded-xl border p-4 text-left transition-all duration-200 hover:-translate-y-0.5 hover:shadow-lg ${
          isSelected
            ? demo.attack
              ? "border-rose-400 bg-rose-500/10 shadow-lg shadow-rose-950/20"
              : "border-emerald-400 bg-emerald-500/10 shadow-lg shadow-emerald-950/20"
            : "border-slate-700/80 bg-slate-950/60 hover:border-indigo-400/70 hover:bg-slate-800/80"
        }`}
      >
        <div className="flex items-center justify-between gap-2">
          <span
            className={`rounded-full px-2 py-1 text-[10px] font-bold uppercase tracking-wide ${
              demo.attack
                ? "bg-rose-500/10 text-rose-300"
                : "bg-emerald-500/10 text-emerald-300"
            }`}
          >
            {demo.attack ? "Attack example" : "Safe example"}
          </span>

          {isSelected && (
            <span className="text-xs font-semibold text-indigo-300">
              Selected
            </span>
          )}
        </div>

        <span className="mt-3 block text-sm font-semibold text-white">
          {demo.title}
        </span>

        <span className="mt-1 block text-xs leading-5 text-slate-400">
          {demo.note}
        </span>
      </button>
    );
  })}
</div>
            <div className="grid gap-3 sm:grid-cols-[8.5rem_1fr]">
              <label className="block text-xs text-slate-400">Method
                <select value={method} onChange={(e) => { setMethod(e.target.value); setSelectedDemo(""); setResult(null); }} className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-3 text-sm text-white focus:border-indigo-400">
                  {["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"].map((item) => <option key={item} value={item}>{item}</option>)}
                </select>
              </label>
              <label className="block text-xs text-slate-400">Path and query
                <input type="text" value={target} onChange={(e) => { setTarget(e.target.value); setSelectedDemo(""); setResult(null); }} placeholder="/api/products?category=books&page=1" autoComplete="off" spellCheck={false} required className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-3 font-mono text-xs text-white placeholder:text-slate-600 focus:border-indigo-400" />
              </label>
            </div>
            {!['GET', 'HEAD'].includes(method) && <label className="block text-xs text-slate-400">Request body<textarea value={body} onChange={(e) => { setBody(e.target.value); setSelectedDemo(""); }} rows={4} className="mt-1 w-full rounded border border-slate-700 bg-slate-950 px-3 py-2.5 font-mono text-xs text-white" /></label>}
            <button disabled={busy} className="flex w-full items-center justify-center gap-2 rounded-lg bg-indigo-600 px-4 py-3 text-sm font-semibold text-white hover:bg-indigo-500 disabled:opacity-50"><Play className="h-4 w-4" />{busy ? "Inspecting request…" : "Send through the WAF gateway"}<ArrowRight className="h-4 w-4" /></button>
            <p className="text-[11px] text-slate-500">Without <code>UPSTREAM_URL</code>, allowed requests receive a labeled mock response and are not forwarded externally.</p>
          </form>
          <div className="space-y-4">
            <section className="rounded-xl border border-slate-800 bg-slate-900/80 p-5">
              <h2 className="mb-4 flex items-center gap-2 font-semibold"><Activity className="h-4 w-4 text-cyan-300" />Runtime telemetry</h2>
              <div className="mb-4 rounded-lg border border-slate-800 bg-slate-950/70 p-3" aria-live="polite">
                <div className="flex items-center justify-between gap-3"><span className="text-xs font-medium text-slate-300">WAF service</span><span className={`inline-flex items-center gap-1.5 text-[11px] font-semibold ${healthUnavailable ? "text-rose-300" : runtimeHealth?.status === "ok" ? "text-emerald-300" : "text-slate-400"}`}><span className={`h-2 w-2 rounded-full ${healthUnavailable ? "bg-rose-400" : runtimeHealth?.status === "ok" ? "bg-emerald-400" : "bg-slate-500"}`} />{healthUnavailable ? "Unavailable" : runtimeHealth?.status === "ok" ? "Connected" : "Checking…"}</span></div>
                {runtimeHealth && <div className="mt-2 space-y-1 text-[10px] text-slate-400"><p>Scoring: <span className="text-slate-200">{runtimeHealth.scoringEngine === "handcrafted-heuristic" ? "Handcrafted heuristic" : runtimeHealth.scoringEngine}</span></p><p>Allowed request destination: <span className={runtimeHealth.upstreamConfigured ? "text-emerald-300" : "text-amber-200"}>{runtimeHealth.upstreamConfigured ? "Configured upstream" : "Local mock response"}</span></p></div>}
                {healthUnavailable && <p className="mt-1 text-[10px] text-rose-200">The health endpoint could not be reached. Check the WAF server connection.</p>}
              </div>
              <div className="grid grid-cols-2 gap-3"><Metric label="Requests" value={metrics.totalRequests} /><Metric label="Blocked" value={metrics.blocked} tone="rose" /><Metric label="Allowed" value={metrics.allowed} tone="green" /><Metric label="Monitored" value={metrics.monitored} tone="amber" /><Metric label="P50 inspection" value={`${metrics.p50LatencyMs.toFixed(2)} ms`} /><Metric label="P95 inspection" value={`${metrics.p95LatencyMs.toFixed(2)} ms`} /></div>
              <DecisionBreakdown metrics={metrics} />
              <p className="mt-3 text-[10px] text-slate-500">In-memory counts reset when the server restarts. Percentages are of inspected live requests.</p>
            </section>
            <section className="rounded-xl border border-slate-800 bg-slate-900/80 p-5"><h2 className="mb-3 text-sm font-semibold">Inspection stages</h2><div className="space-y-2"><Flow icon={<Code2 className="h-4 w-4" />} title="Normalize" text="Decode, parse, and canonicalize request" /><Flow icon={<ShieldAlert className="h-4 w-4" />} title="Inspect" text="Apply deterministic signatures and heuristic score" /><Flow icon={<ShieldCheck className="h-4 w-4" />} title="Enforce policy" text={mode === "ENFORCING" ? "Block high risk or return a response" : "Record suspicious requests and continue"} /></div></section>
          </div>
        </div>
        {result && <ResultPanel result={result} details={result.body && typeof result.body === "object" ? result.body as { reason?: string; matchedRules?: Array<{ id: string; category: string; description: string }> } : null} onDismiss={() => setResult(null)} />}
        <RecentEvents events={events} />
      </div>}

      {activeTab === "evaluation" && <div className="space-y-5"><PageHeading eyebrow="Evaluation" title="See what has actually been measured" text="The current dataset result uses a licensed public request corpus and a fixed 32,840-request holdout. It is request-level, not application-held-out, and does not establish production performance." />
        <div className="grid gap-4 md:grid-cols-3"><InfoCard title="Live process" icon={<Activity className="h-5 w-5 text-cyan-300" />} value={`${metrics.totalRequests} requests`} text={`${metrics.blocked} blocked · ${metrics.allowed} allowed · counters reset with the server`} /><InfoCard title="Smoke corpus" icon={<ShieldCheck className="h-5 w-5 text-emerald-300" />} value={smokeReport?.unique_samples ? `${smokeReport.unique_samples} unique requests` : "Local regression check"} text={smokeReport?.evidence_scope || "Handcrafted examples only; regression evidence, not publication evidence."} /><InfoCard title="Research evaluation" icon={<Database className="h-5 w-5 text-indigo-300" />} value="32,840 test requests" text="WAMM DS-Augmented-v2 · request-level split · BERT-Tiny threshold 0.50" /></div>
        <section className="rounded-xl border border-slate-800 bg-slate-900/80 p-5"><div className="flex flex-wrap items-center justify-between gap-3"><div><h2 className="font-semibold">WAMM DS-Augmented-v2 · held-out evaluation</h2><p className="mt-1 text-xs text-slate-400">32,840 unique requests · seed 42 · 500 request-level bootstrap resamples</p></div><span className="rounded border border-amber-400/20 bg-amber-500/[0.06] px-2 py-1 text-[10px] text-amber-100">Not cross-application validation</span></div>
          <div className="mt-4 grid gap-3 md:grid-cols-3">{[{ name: "Deterministic rules", f1: "93.65%", ci: "93.41–93.88%", precision: "98.46%", recall: "89.28%", fpr: "2.42%" }, { name: "Fine-tuned BERT-Tiny", f1: "87.61%", ci: "87.24–87.96%", precision: "94.18%", recall: "81.89%", fpr: "8.76%" }, { name: "Handcrafted heuristic", f1: "66.94%", ci: "66.42–67.46%", precision: "64.80%", recall: "69.24%", fpr: "65.10%" }].map((lane) => <article key={lane.name} className="rounded-lg border border-slate-800 bg-slate-950 p-4"><h3 className="text-xs font-semibold text-slate-200">{lane.name}</h3><p className="mt-1 text-[10px] text-slate-500">n = 32,840 · F1 95% CI {lane.ci}</p><div className="mt-3 grid grid-cols-2 gap-2 text-[11px]"><Stat label="F1" value={lane.f1} /><Stat label="Precision" value={lane.precision} /><Stat label="Recall" value={lane.recall} /><Stat label="False positive rate" value={lane.fpr} /></div></article>)}</div>
          <p className="mt-4 text-[11px] leading-5 text-slate-400">The trained model is a benchmark artifact; the live gateway still uses the handcrafted score. The current external-model-plus-rules lane makes the same decisions as rules-only under the existing policy. The dataset mixes captured benign requests with generated/scanner attack traffic; it does not establish production or cross-site performance. See <code>research/WAMM_BERT_TINY_RESULTS.md</code> and <code>research/DATASET_PROVENANCE.md</code>.</p></section>
        <section className="rounded-xl border border-slate-800 bg-slate-900/80 p-5"><div className="flex flex-wrap items-center justify-between gap-3"><div><h2 className="font-semibold">Handcrafted smoke benchmark</h2><p className="mt-1 text-xs text-slate-400">Runs 29 unique examples. Repeated timing iterations measure runtime only; they are not extra examples.</p></div><button onClick={runSmoke} disabled={smokeBusy} className="flex items-center gap-2 rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-xs font-semibold hover:border-indigo-400 disabled:opacity-50"><RefreshCw className={`h-3.5 w-3.5 ${smokeBusy ? "animate-spin" : ""}`} />{smokeBusy ? "Running…" : "Run smoke benchmark"}</button></div>
          {smokeReport?.error && <Notice tone="rose">{smokeReport.error}</Notice>}{smokeReport?.message && <p className="mt-4 text-xs text-slate-400">{smokeReport.message}</p>}
          {smokeReport?.metrics_by_lane && <><p className="mt-4 rounded-lg border border-amber-400/20 bg-amber-500/[0.06] p-3 text-[11px] text-amber-100">{smokeReport.evidence_scope || "Regression check on handcrafted examples only."} Do not cite these smoke results as research performance.</p><div className="mt-4 grid gap-3 md:grid-cols-3">{Object.entries(smokeReport.metrics_by_lane).map(([name, m]) => <article key={name} className="rounded-lg border border-slate-800 bg-slate-950 p-4"><h3 className="text-xs font-semibold text-slate-200">{name.replaceAll("_", " ")}</h3><p className="mt-1 text-[10px] text-slate-500">n = {m.n} unique requests</p><div className="mt-3 grid grid-cols-2 gap-2 text-[11px]"><Stat label="Accuracy" value={pct(m.accuracy)} /><Stat label="Precision" value={pct(m.precision)} /><Stat label="Recall" value={pct(m.recall)} /><Stat label="F1" value={pct(m.f1_score)} /><Stat label="FPR" value={pct(m.fpr)} /><Stat label="FNR" value={pct(m.fnr)} /></div></article>)}</div></>}
        </section>
        <section className="rounded-xl border border-slate-800 bg-slate-900/80 p-5"><h2 className="font-semibold">Publication-grade workflow</h2><ol className="mt-3 grid gap-3 text-xs text-slate-300 md:grid-cols-3"><li className="rounded-lg bg-slate-950 p-3"><b className="text-indigo-300">1 · Prepare</b><p className="mt-1 text-slate-400">Document sources, licenses, labels, hashes, and application grouping.</p></li><li className="rounded-lg bg-slate-950 p-3"><b className="text-indigo-300">2 · Split</b><p className="mt-1 text-slate-400">Deduplicate requests and hold out entire applications or attack families.</p></li><li className="rounded-lg bg-slate-950 p-3"><b className="text-indigo-300">3 · Compare</b><p className="mt-1 text-slate-400">Run rules, heuristic, trained model, and CRS baseline with confidence intervals.</p></li></ol><p className="mt-3 text-[11px] text-slate-500">Commands and limitations are in <code>research/PUBLICATION_READINESS.md</code> and the README.</p></section>
      </div>}

      {activeTab === "adaptation" && <div className="space-y-5"><PageHeading eyebrow="Few-Shot Adaptation · Demo" title="Demonstrate profile adaptation" text="The current profile feature adapts route expectations from generated synthetic request samples. It illustrates the software path; it is not a measured few-shot research result." />
        <section className="rounded-xl border border-slate-800 bg-slate-900/80 p-5"><h2 className="font-semibold">Select a synthetic sample budget</h2><p className="mt-1 text-xs text-slate-400">This endpoint creates local example requests for five demonstration routes.</p><div className="mt-4 flex flex-wrap gap-2">{[0, 100, 500, 1000].map((n) => <button key={n} onClick={() => adapt(n)} className={`rounded-lg border px-4 py-2 text-xs font-semibold ${budget === n ? "border-indigo-400 bg-indigo-600 text-white" : "border-slate-700 bg-slate-950 text-slate-300 hover:border-slate-500"}`}>{n} samples</button>)}</div>
          {adaptResult && <div className={`mt-4 rounded-lg border p-4 text-xs ${adaptResult.error ? "border-rose-400/30 bg-rose-500/[0.06] text-rose-100" : "border-emerald-400/20 bg-emerald-500/[0.05] text-emerald-100"}`}>{adaptResult.error ? adaptResult.error : <><b>Profile updated with synthetic demo samples.</b><p className="mt-1 text-slate-300">Budget: {adaptResult.adaptationBudget} · profile routes: {adaptResult.knownEndpointsCount} · evidence type: {adaptResult.evidenceType}</p><p className="mt-1 text-amber-200">This is an interactive software demonstration, not experimental evidence.</p></>}</div>}
        </section>
        <div className="grid gap-4 md:grid-cols-2"><InfoCard title="What the profile tracks" icon={<Cpu className="h-5 w-5 text-indigo-300" />} value="Routes and request shape" text="Known paths, methods, parameter names, and simple payload length summaries." /><InfoCard title="What this does not establish" icon={<AlertTriangle className="h-5 w-5 text-amber-300" />} value="No measured FPR reduction" text="There is no real application traffic, held-out deployment, or comparative adaptation study bundled." /></div>
      </div>}

      {activeTab === "robustness" && <div className="space-y-5"><PageHeading eyebrow="Robustness & Evasion" title="Try representative attack and benign requests" text="These are interactive regression examples, not a comprehensive evasion test suite. Choose a vector to load it into the live gateway." />
        <section className="overflow-hidden rounded-xl border border-slate-800 bg-slate-900/80"><div className="border-b border-slate-800 p-4"><h2 className="font-semibold">Request examples</h2><p className="mt-1 text-xs text-slate-400">Running an example sends it once through the local gateway.</p></div><div className="divide-y divide-slate-800">{demoCases.map((demo) => <div key={demo.id} className="flex flex-wrap items-center justify-between gap-3 p-4"><div><span className={`text-[9px] font-bold uppercase ${demo.attack ? "text-rose-300" : "text-emerald-300"}`}>{demo.attack ? "Attack sample" : "Benign sample"}</span><h3 className="mt-1 text-sm font-semibold">{demo.title}</h3><p className="mt-1 text-[11px] text-slate-400">{demo.note}</p><code className="mt-1 block break-all text-[10px] text-slate-500">{demo.method} {demo.target}</code></div><button onClick={() => chooseDemo(demo, true)} className="flex shrink-0 items-center gap-2 rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-xs text-slate-200 hover:border-indigo-400"><ArrowRight className="h-3.5 w-3.5" />Try in gateway</button></div>)}</div></section>
        <Notice tone="amber">A payload being blocked only confirms behavior for that example. It does not establish general attack detection or bypass resistance.</Notice>
      </div>}

      {activeTab === "dataset" && <div className="space-y-5"><PageHeading eyebrow="Data & Provenance" title="Make evaluation traceable" text="The WAMM DS-Augmented-v2 corpus is source-linked under CC BY 4.0, with a trained BERT-Tiny checkpoint and reproducible request-level evaluation artifacts." />
        <div className="grid gap-4 md:grid-cols-3"><InfoCard title="Dataset files" icon={<Database className="h-5 w-5 text-indigo-300" />} value="Source-linked" text="WAMM DS-Augmented-v2 · CC BY 4.0 · 704,665 upstream records; raw data stays outside Git." /><InfoCard title="Prepared split" icon={<Layers className="h-5 w-5 text-cyan-300" />} value="164,602 unique requests" text="Seeded 70/10/20 request-level split after host-aware canonical deduplication; no application holdout." /><InfoCard title="Model artifact" icon={<Cpu className="h-5 w-5 text-amber-300" />} value="BERT-Tiny trained" text="Checkpoint in models/wamm-bert-tiny. Used in benchmark only; live gateway still uses the heuristic." /></div>
        <section className="rounded-xl border border-slate-800 bg-slate-900/80 p-5"><h2 className="font-semibold">Dataset and model provenance</h2><div className="mt-3 grid gap-2 sm:grid-cols-2">{["WAMM DS-Augmented-v2 · repository pinned to commit 2783eab", "Dataset license: CC BY 4.0 · retrieved 2026-10-22", "704,665 source rows · 1,113 contradictory fingerprints excluded", "189,614 duplicate rows removed · 164,602 unique requests retained", "Seed 42 · 115,380 train · 16,382 validation · 32,840 test", "Google BERT-Tiny base model · Apache-2.0 · one fine-tuning epoch"].map((item) => <div key={item} className="flex items-center gap-2 rounded-lg bg-slate-950 p-3 text-xs text-slate-300"><CheckCircle2 className="h-4 w-4 shrink-0 text-cyan-300" />{item}</div>)}</div><p className="mt-4 text-xs leading-5 text-slate-400">The upstream corpus mixes captured benign traffic and generated/scanner attack traffic. It has no reliable application-family field, so this split does not test cross-site generalization. Full attribution, hashes, and commands: <code>research/DATASET_PROVENANCE.md</code>.</p></section>
      </div>}

      {activeTab === "research" && <div className="space-y-5"><PageHeading eyebrow="Research Manuscript · Draft Notes" title="Describe the current system accurately" text="Use this page as a project overview and a checklist for building defensible publication claims." />
        <section className="rounded-xl border border-slate-800 bg-slate-900/80 p-5"><h2 className="font-semibold">Current implementation</h2><div className="mt-4 grid gap-3 md:grid-cols-2"><ResearchRow title="Canonicalization" detail="Bounded URL decoding, path normalization, and basic HTTP request parsing." /><ResearchRow title="Detection" detail="The live gateway uses deterministic signatures and a handcrafted heuristic; BERT-Tiny is trained for separate benchmark evaluation." /><ResearchRow title="Application profile" detail="In-memory route and request-shape demo, adaptable with synthetic samples." /><ResearchRow title="Gateway" detail="WAF checks requests before a mock response or configured single-origin upstream." /></div><div className="mt-4 rounded-lg border border-amber-400/20 bg-amber-500/[0.06] p-3 text-xs leading-5 text-amber-100">BERT-Tiny achieved F1 0.876 on a 32,840-request random holdout. The dataset split is not application-held-out, and the checkpoint is not loaded by the live gateway.</div></section>
        <section className="rounded-xl border border-slate-800 bg-slate-900/80 p-5"><h2 className="font-semibold">Before writing a results section</h2><ol className="mt-3 space-y-2 text-xs text-slate-300">{["Add a licensed application/source-held-out corpus and test split.", "Audit ambiguous source labels and category conflicts independently.", "Integrate and calibrate the trained checkpoint in the live gateway.", "Compare the same held-out requests against rules-only, heuristic, trained model, and OWASP CRS.", "Expand training data and repeat the study across multiple random seeds.", "Keep smoke tests clearly labeled as regression checks, separate from research evaluation."].map((x, i) => <li key={x} className="flex gap-2"><span className="font-mono text-indigo-300">0{i + 1}</span><span>{x}</span></li>)}</ol><p className="mt-4 text-xs text-slate-500">Detailed workflow: <code>research/PUBLICATION_READINESS.md</code>.</p></section>
      </div>}
    </main>
    <footer className="border-t border-slate-800 bg-slate-900/70"><div className="mx-auto flex max-w-7xl flex-wrap items-center justify-between gap-3 px-4 py-4 text-[10px] text-slate-500 sm:px-6"><span>AppAware-WAF · academic prototype · local in-memory telemetry</span><span>Dashboard access uses your sign-in session. API keys belong in server configuration or trusted API clients.</span></div></footer>
  </div>;
}

function PageHeading({ eyebrow, title, text }: { eyebrow: string; title: string; text: string }) { return <div className="page-hero rounded-xl border border-indigo-300/25 bg-gradient-to-r from-indigo-950/50 to-slate-900/70 p-5 sm:p-6"><p className="text-[10px] font-bold uppercase tracking-[0.18em] text-indigo-200">{eyebrow}</p><h1 className="mt-2 text-xl font-bold tracking-tight text-white sm:text-2xl">{title}</h1><p className="mt-2 max-w-3xl text-xs leading-5 text-indigo-50/75">{text}</p></div>; }
function Notice({ tone, children }: { tone: "amber" | "rose"; children: React.ReactNode }) { return <p className={`rounded-lg border p-3 text-xs ${tone === "amber" ? "border-amber-400/25 bg-amber-500/[0.06] text-amber-100" : "border-rose-400/25 bg-rose-500/[0.06] text-rose-100"}`}>{children}</p>; }
function Metric({ label, value, tone }: { label: string; value: number | string; tone?: "rose" | "green" | "amber" }) { const c = tone === "rose" ? "text-rose-300" : tone === "green" ? "text-emerald-300" : tone === "amber" ? "text-amber-200" : "text-white"; return <div className="rounded-lg border border-slate-800 bg-slate-950/70 p-3"><div className="text-[10px] text-slate-500">{label}</div><div className={`mt-1 font-mono text-sm font-semibold ${c}`}>{value}</div></div>; }
function Flow({ icon, title, text }: { icon: React.ReactNode; title: string; text: string }) { return <div className="flex items-center gap-3 rounded-lg bg-slate-950/70 p-3"><span className="text-indigo-300">{icon}</span><span className="min-w-24 text-xs font-semibold text-slate-200">{title}</span><span className="text-[11px] text-slate-500">{text}</span></div>; }

function ResultPanel({
  result,
  details,
  onDismiss,
}: {
  result: GatewayResult;
  details: {
    reason?: string;
    matchedRules?: Array<{
      id: string;
      category: string;
      description: string;
    }>;
  } | null;
  onDismiss: () => void;
}) {
  const blocked = result.decision === "BLOCK";
  const monitored = result.decision === "MONITOR";
  const attackTypeLabels: Record<string, string> = {
    SQLI: "SQL injection",
    XSS: "Cross-site scripting (XSS)",
    RCE: "Remote code execution attempt",
    TRAVERSAL: "Path traversal / file inclusion",
    SCANNER: "Automated scanner probe",
  };
  const attackTypes = [...new Set((details?.matchedRules ?? []).map((rule) => attackTypeLabels[rule.category] || rule.category))];
  const attackType = attackTypes.length ? attackTypes.join(", ") : blocked ? "High-risk request (heuristic)" : null;
  const decisionExplanation = blocked
  ? "The WAF blocked this request because it matched a security rule or reached the configured blocking threshold."
  : monitored
  ? "The WAF flagged this request for review. In monitoring mode, suspicious requests are recorded rather than blocked."
  : "The request passed the WAF's current security checks and was allowed.";
  const colorClass = blocked
    ? "border-rose-400/30 bg-rose-500/[0.06]"
    : monitored
      ? "border-amber-400/30 bg-amber-500/[0.06]"
      : "border-emerald-400/30 bg-emerald-500/[0.06]";

  const title = blocked
    ? "Request blocked"
    : monitored
      ? "Request monitored"
      : "Request allowed";

  const explanation = blocked
    ? "AppAware-WAF stopped this request because it matched a security rule. It was not forwarded to the upstream application."
    : monitored
      ? "The request was inspected and recorded, but it was not blocked. Monitoring mode allows suspicious requests to continue."
      : "The request passed the WAF inspection. This does not guarantee that the request is safe in every other respect.";

  const risk = result.risk === null ? null : Math.round(result.risk * 100);

  const riskLabel =
    risk === null
      ? "Unavailable"
      : risk >= 70
        ? "High risk"
        : risk >= 30
          ? "Medium risk"
          : "Low risk";

  const riskColor =
    risk === null
      ? "text-slate-300"
      : risk >= 70
        ? "text-rose-300"
        : risk >= 30
          ? "text-amber-200"
          : "text-emerald-300";

  return (
    <section
      aria-live="polite"
      className={`rounded-2xl border p-5 sm:p-6 ${colorClass}`}
    >
      <div className="flex items-start justify-between gap-4">
        <div className="flex items-start gap-3">
          <div className="rounded-xl bg-slate-950/70 p-2">
            {blocked ? (
              <ShieldAlert className="h-6 w-6 text-rose-300" />
            ) : monitored ? (
              <Activity className="h-6 w-6 text-amber-200" />
            ) : (
              <ShieldCheck className="h-6 w-6 text-emerald-300" />
            )}
          </div>

          <div>
            <p className="text-xs font-semibold uppercase tracking-wider text-slate-400">
              Inspection result
            </p>
            <h2
              className={`mt-1 text-xl font-bold ${
                blocked
                  ? "text-rose-200"
                  : monitored
                    ? "text-amber-200"
                    : "text-emerald-200"
              }`}
            >
              {title}
            </h2>
            <p className="mt-1 text-sm text-slate-300">
              HTTP {result.status} · {result.method}
            </p>
          </div>
        </div>

        <button
          type="button"
          aria-label="Dismiss result"
          onClick={onDismiss}
          className="rounded-lg p-2 text-slate-400 transition hover:bg-slate-800 hover:text-white"
        >
          <X className="h-5 w-5" />
        </button>
      </div>


<div className="mt-5 rounded-xl border border-slate-700/70 bg-slate-950/50 p-4">
  <p className="text-sm leading-6 text-slate-200">{explanation}</p>
  <div className="mt-3 grid gap-3 sm:grid-cols-2">
    {attackType && <div className="rounded-lg border border-rose-400/20 bg-rose-500/[0.06] p-3">
      <p className="text-xs font-semibold uppercase tracking-wide text-rose-200">Attack type</p>
      <p className="mt-1 text-sm font-semibold text-white">{attackType}</p>
    </div>}
    <div className="rounded-lg border border-slate-700 bg-slate-950/70 p-3">
      <p className="text-xs font-semibold text-white">{blocked ? "Why did the WAF block it?" : "Why this decision?"}</p>
      <p className="mt-1 text-xs leading-5 text-slate-300">{details?.reason || decisionExplanation}</p>
    </div>
  </div>
</div>


      <div className="my-5 grid grid-cols-2 gap-3 sm:grid-cols-4">
        <div className="rounded-xl border border-slate-700/70 bg-slate-950/50 p-3">
          <p className="text-xs text-slate-400">WAF decision</p>
          <p className="mt-2 font-semibold text-white">{result.decision}</p>
        </div>

        <div className="rounded-xl border border-slate-700/70 bg-slate-950/50 p-3">
          <p className="text-xs text-slate-400">Risk score</p>
          <p className={`mt-2 font-semibold ${riskColor}`}>
            {risk === null ? "—" : `${risk} / 100`}
          </p>
          <p className={`mt-1 text-xs ${riskColor}`}>{riskLabel}</p>
        </div>

        <div className="rounded-xl border border-slate-700/70 bg-slate-950/50 p-3">
          <p className="text-xs text-slate-400">Gateway mode</p>
          <p className="mt-2 break-words text-sm font-semibold text-white">
            {result.mode === "mock-demo" ? "Local demo" : result.mode}
          </p>
        </div>

        <div className="rounded-xl border border-slate-700/70 bg-slate-950/50 p-3">
          <p className="text-xs text-slate-400">Event ID</p>
          <p
            title={result.eventId}
            className="mt-2 break-all font-mono text-xs text-slate-200"
          >
            {result.eventId}
          </p>
        </div>
      </div>

      {details?.matchedRules && details.matchedRules.length > 0 && (
        <div className="mb-5">
          <h3 className="text-sm font-semibold text-white">
            Matched security rules
          </h3>
          <p className="mt-1 text-xs text-slate-400">These rule matches determined the detected attack type above.</p>
          <div className="mt-3 flex flex-wrap gap-2">
            {details.matchedRules.map((rule) => (
              <span
                key={rule.id}
                title={rule.description}
                className="rounded-lg border border-rose-400/20 bg-rose-500/10 px-3 py-2 text-xs text-rose-200"
              >
                {rule.id} · {rule.category}
              </span>
            ))}
          </div>
          <p className="mt-2 text-xs text-slate-500">
            Hover over a rule to read its description.
          </p>
        </div>
      )}

      <details className="group rounded-xl border border-slate-700/70 bg-slate-950/50">
        <summary className="flex cursor-pointer list-none items-center justify-between gap-3 p-4 text-sm font-semibold text-slate-200">
          <span>View technical gateway response</span>
          <span className="text-xs text-indigo-300 group-open:hidden">
            Show JSON ↓
          </span>
          <span className="hidden text-xs text-indigo-300 group-open:inline">
            Hide JSON ↑
          </span>
        </summary>
        <pre className="max-h-72 overflow-auto border-t border-slate-700/70 p-4 text-xs leading-5 text-slate-300">
          {JSON.stringify(result.body, null, 2)}
        </pre>
      </details>

      <p className="mt-4 break-all font-mono text-xs leading-5 text-slate-500">
        Request: {result.method} {result.target}
      </p>
    </section>
  );
}


function DecisionBreakdown({ metrics }: { metrics: WafMetrics }) {
  const decisions = [
    { label: "Allowed", count: metrics.allowed, color: "#34d399", barClass: "bg-emerald-400" },
    { label: "Monitored", count: metrics.monitored, color: "#fbbf24", barClass: "bg-amber-400" },
    { label: "Blocked", count: metrics.blocked, color: "#fb7185", barClass: "bg-rose-400" },
  ];
  const total = decisions.reduce((sum, decision) => sum + decision.count, 0);
  let offset = 0;
  const gradient = total === 0
    ? "#1e293b 0% 100%"
    : decisions.map((decision) => {
      const start = offset / total * 100;
      offset += decision.count;
      return `${decision.color} ${start}% ${offset / total * 100}%`;
    }).join(", ");

  return (
    <section className="mt-5 border-t border-slate-800 pt-4" aria-label="Live request decision breakdown">
      <div className="flex items-center justify-between gap-2"><h3 className="text-xs font-semibold text-slate-200">Request outcomes</h3><span className="text-[10px] text-slate-500">{total.toLocaleString()} inspected</span></div>
      <div className="mt-4 grid grid-cols-[112px_1fr] items-center gap-4 sm:grid-cols-[128px_1fr]">
        <div className="relative mx-auto h-28 w-28 rounded-full sm:h-32 sm:w-32" role="img" aria-label={total ? decisions.map((item) => `${item.label} ${pct(item.count / total)}`).join(", ") : "No request outcomes yet"} style={{ background: `conic-gradient(${gradient})` }}>
          <div className="absolute inset-[18px] flex flex-col items-center justify-center rounded-full bg-slate-900 text-center"><span className="text-xl font-bold text-white">{total ? total.toLocaleString() : "—"}</span><span className="text-[9px] text-slate-400">requests</span></div>
        </div>
        <div className="space-y-3">{decisions.map((decision) => {
          const share = total ? decision.count / total : 0;
          return <div key={decision.label}>
            <div className="mb-1 flex items-center justify-between gap-2 text-[10px]"><span className="flex items-center gap-1.5 text-slate-300"><span className={`h-2 w-2 rounded-full ${decision.barClass}`} />{decision.label}</span><span className="font-mono text-slate-300">{pct(share)} <span className="text-slate-500">({decision.count})</span></span></div>
            <div className="h-1.5 overflow-hidden rounded-full bg-slate-800" role="progressbar" aria-label={`${decision.label} share`} aria-valuenow={Math.round(share * 100)} aria-valuemin={0} aria-valuemax={100}><div className={`h-full rounded-full ${decision.barClass}`} style={{ width: `${share * 100}%` }} /></div>
          </div>;
        })}</div>
      </div>
      {total === 0 && <p className="mt-3 text-center text-[10px] text-slate-500">Send a request through the gateway to populate this chart.</p>}
    </section>
  );
}

function RecentEvents({ events }: { events: SecurityEvent[] }) {
  const [filter, setFilter] = useState<"ALL" | "ALLOW" | "BLOCK" | "MONITOR">("ALL");
  const filteredEvents = events.filter((event) => filter === "ALL" || event.decision === filter);
  const filterOptions = [
    { label: "All", value: "ALL" },
    { label: "Allowed", value: "ALLOW" },
    { label: "Blocked", value: "BLOCK" },
    { label: "Monitored", value: "MONITOR" },
  ] as const;

  return (
    <section className="rounded-2xl border border-slate-800 bg-slate-900/80 p-5 sm:p-6">
      <div className="flex flex-col justify-between gap-4 sm:flex-row sm:items-center">
        <div>
          <h2 className="text-lg font-semibold text-white">Recent security events</h2>
          <p className="mt-1 text-xs text-slate-400">Review inspected requests and filter by the WAF decision.</p>
        </div>
        <span className="w-fit rounded-full border border-slate-700 bg-slate-950 px-3 py-1.5 text-xs text-slate-300">
          {filteredEvents.length} of {events.length} events
        </span>
      </div>
      <div className="mt-5 flex flex-wrap gap-2" aria-label="Filter security events by decision">
        {filterOptions.map((option) => (
          <button key={option.value} type="button" onClick={() => setFilter(option.value)} aria-pressed={filter === option.value}
            className={filter === option.value
              ? "rounded-xl border border-indigo-400 bg-indigo-500/15 px-3 py-2 text-xs font-medium text-indigo-200"
              : "rounded-xl border border-slate-700 bg-slate-950 px-3 py-2 text-xs font-medium text-slate-400 hover:border-slate-500 hover:text-white"}>
            {option.label}
          </button>
        ))}
      </div>
      {filteredEvents.length === 0 ? (
        <div className="mt-5 rounded-xl border border-dashed border-slate-700 px-4 py-10 text-center">
          <ShieldCheck className="mx-auto h-8 w-8 text-slate-500" />
          <p className="mt-3 text-sm font-medium text-slate-300">{events.length === 0 ? "No security events yet" : "No events match this decision filter"}</p>
          <p className="mt-1 text-xs text-slate-500">{events.length === 0 ? "Send a request through the Live Gateway to see it here." : "Choose another decision filter or show all events."}</p>
          {events.length > 0 && <button type="button" onClick={() => setFilter("ALL")} className="mt-4 rounded-lg border border-slate-700 px-3 py-2 text-xs text-slate-300 hover:bg-slate-800">Show all events</button>}
        </div>
      ) : (
        <div className="mt-5 overflow-x-auto rounded-xl border border-slate-800">
          <table className="w-full min-w-[540px] text-left text-sm">
            <thead className="bg-slate-950 text-xs text-slate-400"><tr>
              <th scope="col" className="px-4 py-3 font-medium">Time</th>
              <th scope="col" className="px-4 py-3 font-medium">Request</th>
              <th scope="col" className="px-4 py-3 font-medium">Decision</th>
              <th scope="col" className="px-4 py-3 text-right font-medium">Risk</th>
            </tr></thead>
            <tbody>
              {filteredEvents.slice(0, 50).map((event) => {
                const risk = Math.round(event.riskScore * 100);
                const decisionStyle = event.decision === "BLOCK"
                  ? "border-rose-500/30 bg-rose-500/10 text-rose-300"
                  : event.decision === "MONITOR"
                    ? "border-amber-500/30 bg-amber-500/10 text-amber-200"
                    : "border-emerald-500/30 bg-emerald-500/10 text-emerald-300";
                return (
                  <tr key={event.eventId} className="border-t border-slate-800 transition hover:bg-slate-800/40">
                    <td className="whitespace-nowrap px-4 py-3 text-xs text-slate-400">{new Date(event.timestamp).toLocaleTimeString()}</td>
                    <td className="max-w-[360px] px-4 py-3">
                      <div className="font-mono text-xs text-slate-200">{event.method}</div>
                      <div className="mt-1 truncate font-mono text-xs text-slate-400" title={event.path}>{event.path}</div>
                    </td>
                    <td className="px-4 py-3"><span className={"inline-flex rounded-full border px-2.5 py-1 text-[11px] font-semibold " + decisionStyle}>{event.decision}</span></td>
                    <td className="px-4 py-3 text-right">
                      <span className={risk >= 70 ? "font-mono font-semibold text-rose-300" : risk >= 30 ? "font-mono font-semibold text-amber-200" : "font-mono font-semibold text-emerald-300"}>{risk}</span>
                      <span className="text-xs text-slate-500"> / 100</span>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
          {filteredEvents.length > 50 && <p className="border-t border-slate-800 px-4 py-3 text-xs text-slate-500">Showing the first 50 events.</p>}
        </div>
      )}
    </section>
  );
}
function InfoCard({ title, icon, value, text }: { title: string; icon: React.ReactNode; value: string; text: string }) { return <article className="rounded-xl border border-slate-800 bg-slate-900/80 p-5"><div className="flex items-center gap-2">{icon}<h2 className="text-xs font-semibold text-slate-200">{title}</h2></div><p className="mt-3 text-lg font-bold text-white">{value}</p><p className="mt-1 text-xs leading-5 text-slate-400">{text}</p></article>; }
function Stat({ label, value }: { label: string; value: string }) { return <div><div className="text-[10px] text-slate-500">{label}</div><div className="mt-1 truncate text-xs font-semibold text-slate-200">{value}</div></div>; }
function ResearchRow({ title, detail }: { title: string; detail: string }) { return <div className="rounded-lg border border-slate-800 bg-slate-950/70 p-3"><h3 className="text-xs font-semibold text-indigo-200">{title}</h3><p className="mt-1 text-[11px] leading-4 text-slate-400">{detail}</p></div>; }
function pct(value: number | null | undefined) { return value === null || value === undefined ? "n/a" : `${(value * 100).toFixed(2)}%`; }
