import { ParsedRequest } from "./canonicalizer.ts";

export interface EndpointProfile {
  path: string;
  allowedMethods: Set<string>;
  observedSamples: number;
  knownParams: Set<string>;
  payloadLengths: number[];
  p95PayloadLen: number;
}

export class ApplicationProfile {
  public appId: string;
  public adaptationBudget: number;
  public endpoints: Map<string, EndpointProfile>;

  constructor(appId = "target_app") {
    this.appId = appId;
    this.adaptationBudget = 0;
    this.endpoints = new Map();
    this.initDefaultBaseline();
  }

  private initDefaultBaseline() {
    // Seed standard base routes for demo
    const defaultRoutes = ["/api/v1/auth/login", "/api/v1/users", "/api/v1/products", "/api/v1/orders", "/health"];
    for (const r of defaultRoutes) {
      this.endpoints.set(r, {
        path: r,
        allowedMethods: new Set(["GET", "POST"]),
        observedSamples: 25,
        knownParams: new Set(["page", "limit", "id", "q", "token"]),
        payloadLengths: [64, 128, 256, 512],
        p95PayloadLen: 768,
      });
    }
  }

  public adaptFromBenignSamples(samples: { path: string; method: string; queryParams: Record<string, string>; bodyLen: number }[]) {
    this.adaptationBudget = samples.length;
    for (const s of samples) {
      let ep = this.endpoints.get(s.path);
      if (!ep) {
        ep = {
          path: s.path,
          allowedMethods: new Set([s.method.toUpperCase()]),
          observedSamples: 0,
          knownParams: new Set(),
          payloadLengths: [],
          p95PayloadLen: 1024,
        };
        this.endpoints.set(s.path, ep);
      }
      ep.observedSamples++;
      ep.allowedMethods.add(s.method.toUpperCase());
      ep.payloadLengths.push(s.bodyLen);
      for (const p of Object.keys(s.queryParams)) {
        ep.knownParams.add(p);
      }
      if (ep.payloadLengths.length >= 5) {
        const sorted = [...ep.payloadLengths].sort((a, b) => a - b);
        ep.p95PayloadLen = sorted[Math.floor(0.95 * sorted.length)];
      }
    }
  }

  public evaluate(parsed: ParsedRequest): {
    score: number;
    isKnownRoute: boolean;
    adaptationBudget: number;
    reason: string;
  } {
    let ep = this.endpoints.get(parsed.canonicalPath);
    if (!ep) {
      for (const [rPath, rProfile] of this.endpoints.entries()) {
        if (parsed.canonicalPath.startsWith(rPath) && rPath !== "/") {
          ep = rProfile;
          break;
        }
      }
    }

    if (!ep) {
      const unfamiliarity = this.adaptationBudget >= 100 ? 0.2 : 0.05;
      return {
        score: unfamiliarity,
        isKnownRoute: false,
        adaptationBudget: this.adaptationBudget,
        reason: "Unregistered route path",
      };
    }

    let anomalyScore = 0.0;
    const reasons: string[] = [];

    // Method mismatch
    if (!ep.allowedMethods.has(parsed.method.toUpperCase())) {
      anomalyScore += 0.35;
      reasons.push(`Method ${parsed.method} not in expected methods`);
    }

    // Param deviation
    if (ep.observedSamples >= 30) {
      const incomingParams = Object.keys(parsed.queryParams);
      const unknown = incomingParams.filter((p) => !ep!.knownParams.has(p));
      if (unknown.length > 0) {
        anomalyScore += Math.min(0.25, 0.08 * unknown.length);
        reasons.push(`Unrecognized parameters: ${unknown.join(", ")}`);
      }
    }

    // Payload size anomaly
    const bodyLen = (parsed.body || "").length;
    if (ep.observedSamples >= 15 && bodyLen > ep.p95PayloadLen * 3 + 256) {
      anomalyScore += 0.25;
      reasons.push(`Payload size (${bodyLen} bytes) exceeds P95 baseline`);
    }

    return {
      score: Math.min(1.0, anomalyScore),
      isKnownRoute: true,
      adaptationBudget: this.adaptationBudget,
      reason: reasons.length ? reasons.join("; ") : "Matches learned application profile",
    };
  }
}
