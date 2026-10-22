import "dotenv/config";
import express, { Request, Response, NextFunction } from "express";
import path from "path";
import fs from "fs";
import { execFile } from "child_process";
import { timingSafeEqual } from "crypto";
import { fileURLToPath } from "url";
import { WafPipelineTS } from "./src/waf/pipeline.ts";
import { SecurityEvent, WafMetrics } from "./src/waf/types.ts";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const port = Number(process.env.PORT || 3000);
const adminToken = process.env.WAF_ADMIN_TOKEN?.trim() || "";
const configuredMode = (process.env.WAF_MODE || "ENFORCING").toUpperCase();
if (!["ENFORCING", "MONITORING", "SIMULATION"].includes(configuredMode)) {
  throw new Error("WAF_MODE must be ENFORCING, MONITORING, or SIMULATION.");
}
const trustedProxyRanges = (process.env.WAF_TRUST_PROXY || "")
  .split(",")
  .map((range) => range.trim())
  .filter(Boolean);

if (trustedProxyRanges.some((range) => range.toLowerCase() === "true")) {
  throw new Error("WAF_TRUST_PROXY must contain explicit trusted proxy IPs/CIDRs, never 'true'.");
}
if (trustedProxyRanges.length) app.set("trust proxy", trustedProxyRanges);
else app.set("trust proxy", false);

if (process.env.NODE_ENV === "production" && adminToken.length < 32) {
  throw new Error("Set WAF_ADMIN_TOKEN to a random value of at least 32 characters in production.");
}

const upstreamUrl = process.env.UPSTREAM_URL ? new URL(process.env.UPSTREAM_URL) : null;
if (upstreamUrl && (!['http:', 'https:'].includes(upstreamUrl.protocol) || upstreamUrl.username || upstreamUrl.password || upstreamUrl.pathname !== "/" || upstreamUrl.search || upstreamUrl.hash)) {
  throw new Error("UPSTREAM_URL must be an http(s) origin without credentials, path, query, or fragment.");
}

function requireAdmin(req: Request, res: Response, next: NextFunction) {
  if (!adminToken) {
    if (process.env.NODE_ENV === "production") {
      res.status(503).json({ error: "Management API is disabled until WAF_ADMIN_TOKEN is configured." });
      return;
    }
    next();
    return;
  }

  const supplied = req.header("authorization")?.replace(/^Bearer\s+/i, "") || "";
  const expectedBytes = Buffer.from(adminToken);
  const suppliedBytes = Buffer.from(supplied);
  if (expectedBytes.length !== suppliedBytes.length || !timingSafeEqual(expectedBytes, suppliedBytes)) {
    res.status(401).json({ error: "Valid admin bearer token required." });
    return;
  }
  next();
}

// Body parser
app.use(express.json({ limit: "5mb" }));
app.use(express.urlencoded({ extended: true, limit: "5mb" }));
app.use(express.text({ type: ["text/*", "application/xml", "application/octet-stream"], limit: "5mb" }));
app.use("/api/waf", requireAdmin);

// Initialize WAF Pipeline
const waf = new WafPipelineTS(configuredMode as "ENFORCING" | "MONITORING" | "SIMULATION");

// In-memory observability state
const securityLogs: SecurityEvent[] = [];
const metrics: WafMetrics = {
  totalRequests: 0,
  allowed: 0,
  monitored: 0,
  blocked: 0,
  totalRuleMatches: 0,
  p50LatencyMs: 0,
  p95LatencyMs: 0,
  p99LatencyMs: 0,
  categoryCounts: {
    SQLI: 0,
    XSS: 0,
    RCE: 0,
    TRAVERSAL: 0,
    SCANNER: 0,
  },
};
const latencies: number[] = [];

function recordEvent(event: SecurityEvent) {
  securityLogs.unshift(event);
  if (securityLogs.length > 200) securityLogs.pop();

  metrics.totalRequests++;
  if (event.decision === "BLOCK") metrics.blocked++;
  else if (event.decision === "MONITOR") metrics.monitored++;
  else metrics.allowed++;

  for (const r of event.matchedRules) {
    metrics.totalRuleMatches++;
    if (r.category in metrics.categoryCounts) {
      metrics.categoryCounts[r.category]++;
    }
  }

  latencies.push(event.latencies.totalMs);
  if (latencies.length > 500) latencies.shift();
  const sorted = [...latencies].sort((a, b) => a - b);
  metrics.p50LatencyMs = sorted[Math.floor(sorted.length * 0.5)] || 0;
  metrics.p95LatencyMs = sorted[Math.floor(sorted.length * 0.95)] || 0;
  metrics.p99LatencyMs = sorted[Math.floor(sorted.length * 0.99)] || 0;
}

app.get("/healthz", (_req: Request, res: Response) => {
  res.json({ status: "ok", scoringEngine: "handcrafted-heuristic", upstreamConfigured: Boolean(upstreamUrl) });
});

// ============================================================================
// 1. MOCK UPSTREAM WEB APPLICATION (/upstream/*)
// ============================================================================
app.get("/upstream/api/users", (req: Request, res: Response) => {
  res.json({
    status: "success",
    app: "Internal Upstream Service",
    users: [
      { id: 1, name: "Alice Security", role: "DevSecOps" },
      { id: 2, name: "Bob Engineer", role: "Backend" },
    ],
  });
});

app.get("/upstream/api/products", (req: Request, res: Response) => {
  res.json({
    status: "success",
    products: [
      { id: 101, title: "Hardware Security Module (HSM)", price: 4999 },
      { id: 102, title: "Next-Gen Firewall Appliance", price: 12500 },
    ],
  });
});

app.post("/upstream/api/orders", (req: Request, res: Response) => {
  res.json({
    status: "created",
    orderId: "ord-" + Math.random().toString(36).slice(2, 8),
    received: req.body,
  });
});

app.all("/upstream/*", (req: Request, res: Response) => {
  res.json({
    status: "ok",
    message: "Handled by Upstream Protected Target",
    method: req.method,
    path: req.path.replace("/upstream", ""),
    query: req.query,
  });
});

// ============================================================================
// 2. REVERSE PROXY GATEWAY WITH LIVE WAF INTERCEPTION (/proxy/*)
// ============================================================================
app.all("/proxy/*", async (req: Request, res: Response) => {
  // Reconstruct HTTP request stream for WAF inspection
  const targetPath = req.originalUrl.replace(/^\/proxy/, "") || "/";
  if (!targetPath.startsWith("/") || targetPath.startsWith("//") || targetPath.includes("\\")) {
    res.status(400).json({ error: "Invalid proxy request target." });
    return;
  }
  let bodyStr = "";
  if (typeof req.body === "object") {
    bodyStr = JSON.stringify(req.body);
  } else if (typeof req.body === "string") {
    bodyStr = req.body;
  }

  let rawRequest = `${req.method} ${targetPath} HTTP/1.1\r\n`;
  rawRequest += `Host: ${req.headers.host || "gateway.local"}\r\n`;
  for (const [k, v] of Object.entries(req.headers)) {
    if (k !== "host" && typeof v === "string") {
      rawRequest += `${k}: ${v}\r\n`;
    }
  }
  rawRequest += `\r\n${bodyStr}`;

  // Execute full inspection chain through WAF
  // Express resolves req.ip through only the explicitly trusted proxy ranges above.
  // With no WAF_TRUST_PROXY configured, the socket peer is used and X-Forwarded-For is ignored.
  const clientIp = req.ip || req.socket.remoteAddress || "unknown";
  const event = waf.inspect(rawRequest, clientIp);
  recordEvent(event);

  // Set WAF Response Audit Headers
  res.setHeader("X-WAF-Decision", event.decision);
  res.setHeader("X-WAF-Risk-Score", event.riskScore.toString());
  res.setHeader("X-WAF-Event-ID", event.eventId);
  res.setHeader("X-WAF-Latency-MS", event.latencies.totalMs.toString());

  // ENFORCEMENT: If BLOCK, terminate request immediately with HTTP 403 Forbidden
  if (event.decision === "BLOCK") {
    res.status(403).json({
      error: "403 Forbidden - Request Blocked by AppAware WAF",
      eventId: event.eventId,
      reason: event.decisionReason,
      riskScore: event.riskScore,
      matchedRules: event.matchedRules.map((r) => ({
        id: r.ruleId,
        category: r.category,
        description: r.description,
      })),
      timestamp: event.timestamp,
    });
    return;
  }

  if (!upstreamUrl) {
    // Explicit local demo fallback. Configure UPSTREAM_URL to enable real proxying.
    res.setHeader("X-WAF-Upstream-Mode", "mock-demo");
    res.json({
      gatewayStatus: "MOCK_UPSTREAM_RESPONSE",
      wafDecision: event.decision,
      wafRiskScore: event.riskScore,
      message: "No UPSTREAM_URL is configured; this request was not forwarded to another application.",
      targetPath,
      method: req.method,
      query: req.query,
      body: req.body,
    });
    return;
  }

  try {
    const targetUrl = new URL(targetPath, `${upstreamUrl.origin}/`);
    if (targetUrl.origin !== upstreamUrl.origin) {
      res.status(400).json({ error: "Proxy target must remain on the configured upstream origin." });
      return;
    }

    const headers = new Headers();
    const hopByHop = new Set(["connection", "content-encoding", "content-length", "host", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade", "forwarded"]);
    for (const [name, value] of Object.entries(req.headers)) {
      const lowerName = name.toLowerCase();
      if (!hopByHop.has(lowerName) && !lowerName.startsWith("x-forwarded-") && typeof value === "string") headers.set(name, value);
    }
    headers.set("x-forwarded-for", clientIp);

    const hasBody = !["GET", "HEAD"].includes(req.method.toUpperCase()) && req.body !== undefined;
    const body = !hasBody ? undefined : typeof req.body === "string" ? req.body : Buffer.from(JSON.stringify(req.body));
    const upstreamResponse = await fetch(targetUrl, {
      method: req.method,
      headers,
      body,
      redirect: "manual",
      signal: AbortSignal.timeout(10000),
    });

    const responseHopByHop = new Set(["connection", "content-encoding", "content-length", "keep-alive", "transfer-encoding", "upgrade"]);
    upstreamResponse.headers.forEach((value, name) => {
      if (!responseHopByHop.has(name.toLowerCase())) res.setHeader(name, value);
    });
    res.setHeader("X-WAF-Decision", event.decision);
    res.setHeader("X-WAF-Risk-Score", event.riskScore.toString());
    res.setHeader("X-WAF-Event-ID", event.eventId);
    res.setHeader("X-WAF-Latency-MS", event.latencies.totalMs.toString());
    res.setHeader("X-WAF-Upstream-Mode", "configured-upstream");
    res.status(upstreamResponse.status);

    if (!upstreamResponse.body || req.method.toUpperCase() === "HEAD") {
      res.end();
      return;
    }

    const maxResponseBytes = 10 * 1024 * 1024;
    const declaredLength = Number(upstreamResponse.headers.get("content-length") || 0);
    if (declaredLength > maxResponseBytes) {
      res.status(502).json({ error: "Upstream response exceeded the 10 MiB gateway limit." });
      return;
    }
    const chunks: Buffer[] = [];
    let responseBytes = 0;
    for await (const chunk of upstreamResponse.body) {
      responseBytes += chunk.byteLength;
      if (responseBytes > maxResponseBytes) {
        res.status(502).json({ error: "Upstream response exceeded the 10 MiB gateway limit." });
        return;
      }
      chunks.push(Buffer.from(chunk));
    }
    res.end(Buffer.concat(chunks));
  } catch (error) {
    console.error("[Upstream Proxy Error]", error);
    if (!res.headersSent) res.status(502).json({ error: "Configured upstream request failed or timed out." });
    else res.destroy(error as Error);
  }
});

// ============================================================================
// 3. WAF MANAGEMENT & TELEMETRY REST APIs
// ============================================================================
app.post("/api/waf/inspect", (req: Request, res: Response) => {
  const { request, customHeuristicScore } = req.body;
  if (typeof request !== "string" || request.length === 0 || request.length > 1024 * 1024) {
    res.status(400).json({ error: "'request' must be a non-empty string no larger than 1 MiB." });
    return;
  }
  if (customHeuristicScore !== undefined && (typeof customHeuristicScore !== "number" || customHeuristicScore < 0 || customHeuristicScore > 1)) {
    res.status(400).json({ error: "customHeuristicScore must be a number between 0 and 1." });
    return;
  }
  const event = waf.inspect(request, req.ip || req.socket.remoteAddress || "unknown", customHeuristicScore);
  recordEvent(event);
  res.json(event);
});

app.get("/api/waf/metrics", (_req: Request, res: Response) => {
  res.json(metrics);
});

app.get("/api/waf/events", (_req: Request, res: Response) => {
  res.json(securityLogs);
});

app.get("/api/waf/policy/mode", (_req: Request, res: Response) => {
  res.json({ mode: waf.policy.mode });
});

app.post("/api/waf/policy/mode", (req: Request, res: Response) => {
  const { mode } = req.body;
  if (["ENFORCING", "MONITORING", "SIMULATION"].includes(mode)) {
    waf.policy.mode = mode;
    res.json({ status: "success", mode: waf.policy.mode });
  } else {
    res.status(400).json({ error: "Invalid mode" });
  }
});

app.post("/api/waf/adapt", (req: Request, res: Response) => {
  const { budget } = req.body;
  const sampleBudget = Number(budget);
  if (!Number.isInteger(sampleBudget) || ![0, 100, 500, 1000].includes(sampleBudget)) {
    res.status(400).json({ error: "budget must be one of the demo values: 0, 100, 500, or 1000." });
    return;
  }
  
  // Seed sample benign profiles based on requested adaptation budget (0, 100, 500, 1000)
  const syntheticSamples: any[] = [];
  const paths = ["/api/v1/auth/login", "/api/v1/users", "/api/v1/products", "/api/v1/orders", "/api/v1/search"];
  for (let i = 0; i < sampleBudget; i++) {
    syntheticSamples.push({
      path: paths[i % paths.length],
      method: i % 3 === 0 ? "POST" : "GET",
      queryParams: { page: String((i % 10) + 1), limit: "20" },
      bodyLen: (i * 37) % 512,
    });
  }

  waf.profile.adaptFromBenignSamples(syntheticSamples);
  res.json({
    status: "adapted",
    evidenceType: "synthetic_demo_samples",
    researchEvidence: false,
    adaptationBudget: sampleBudget,
    knownEndpointsCount: waf.profile.endpoints.size,
    endpoints: Array.from(waf.profile.endpoints.keys()),
  });
});

app.get("/api/waf/benchmark/results", (_req: Request, res: Response) => {
  const benchmarkFile = path.join(__dirname, "benchmark_results.json");
  if (fs.existsSync(benchmarkFile)) {
    try {
      const data = JSON.parse(fs.readFileSync(benchmarkFile, "utf-8"));
      return res.json(data);
    } catch {
      // Fallback
    }
  }
  res.json({ available: false, message: "No benchmark report exists yet. Run the smoke benchmark or the group-held-out dataset evaluation." });
});

app.post("/api/waf/benchmark/run", (_req: Request, res: Response) => {
  const pythonCommand = process.platform === "win32" ? "python" : "python3";
  execFile(pythonCommand, ["scripts/benchmark_waf.py"], { cwd: __dirname, timeout: 120000 }, (error, stdout, stderr) => {
    if (error) {
      console.error("[Benchmark Error]", error);
      res.status(500).json({ error: stderr || error.message, output: stdout });
      return;
    }
    const benchmarkFile = path.join(__dirname, "benchmark_results.json");
    if (fs.existsSync(benchmarkFile)) {
      try {
        const data = JSON.parse(fs.readFileSync(benchmarkFile, "utf-8"));
        return res.json({ status: "success", data, output: stdout });
      } catch (err: any) {
        return res.status(500).json({ error: err.message });
      }
    }
    res.status(500).json({ error: "Benchmark completed without producing a readable report.", output: stdout });
  });
});

// ============================================================================
// 4. VITE DEV SERVER INTEGRATION OR STATIC PRODUCTION ASSETS
// ============================================================================
async function startServer() {
  if (process.env.NODE_ENV !== "production") {
    const { createServer: createViteServer } = await import("vite");
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    app.use(express.static(path.join(__dirname, "dist")));
    app.get("*", (_req: Request, res: Response) => {
      res.sendFile(path.join(__dirname, "dist", "index.html"));
    });
  }

  app.listen(port, "0.0.0.0", () => {
    console.log(`[AppAware-WAF] Server & Reverse Proxy running at http://localhost:${port}`);
    console.log(`[AppAware-WAF] Reverse Proxy Gateway live on /proxy/*`);
  });
}

startServer();
