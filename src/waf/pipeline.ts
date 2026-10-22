import { parseHttpRequest, ParsedRequest } from "./canonicalizer.ts";
import { inspectDeterministicRules, RuleMatch } from "./rules.ts";
import { ApplicationProfile } from "./profile.ts";
import { PolicyEngine } from "./policy.ts";
import { SecurityEvent } from "./types.ts";

export class WafPipelineTS {
  public profile: ApplicationProfile;
  public policy: PolicyEngine;

  constructor(mode: "ENFORCING" | "MONITORING" | "SIMULATION" = "ENFORCING") {
    this.profile = new ApplicationProfile();
    this.policy = new PolicyEngine({ mode });
  }

  // Handcrafted lexical and punctuation heuristic. This is not a trained Transformer model.
  public computeHeuristicScore(text: string): number {
    if (!text) return 0.0;
    const lower = text.toLowerCase();
    const suspiciousSubwords = [
      "union", "select", "insert", "delete", "drop", "update", "exec", "xp_", "char(", "concat(",
      "<script", "javascript:", "onerror=", "onload=", "eval(", "alert(", "document.cookie",
      "../", "..\\", "etc/passwd", "cmd.exe", "powershell", "/bin/sh", "/bin/bash", "whoami",
      "' or '", '" or "', "admin'--", "1=1", "sleep(", "benchmark("
    ];

    let hits = 0;
    let weight = 0;
    for (const sub of suspiciousSubwords) {
      if (lower.includes(sub)) {
        hits++;
        weight += sub.length > 5 ? 0.35 : 0.2;
      }
    }

    if (hits === 0) {
      // Check character entropy / unusual special characters
      const specialCharCount = (text.match(/[%&?=<>{}\[\]$'";]/g) || []).length;
      const ratio = specialCharCount / Math.max(1, text.length);
      return ratio > 0.35 ? 0.45 : 0.02;
    }

    return Math.min(0.99, weight);
  }

  public inspect(rawRequest: string, clientIp = "127.0.0.1", customHeuristicScore?: number): SecurityEvent {
    const t0 = performance.now();

    // 1. Canonicalization
    const tCanon0 = performance.now();
    const parsed = parseHttpRequest(rawRequest);
    const tCanon = performance.now() - tCanon0;

    // 2. Deterministic Rules
    const tRules0 = performance.now();
    const { score: detScore, matches } = inspectDeterministicRules(parsed);
    const tRules = performance.now() - tRules0;

    // 3. Application Profile
    const profileEval = this.profile.evaluate(parsed);
    const profileScore = profileEval.score;

    // 4. Handcrafted heuristic scoring (not a trained model)
    const tHeuristic0 = performance.now();
    const heuristicScore = customHeuristicScore !== undefined ? customHeuristicScore : this.computeHeuristicScore(parsed.canonicalText);
    const tHeuristic = performance.now() - tHeuristic0;

    // 5. Policy Decision
    const tPol0 = performance.now();
    const decision = this.policy.evaluate(detScore, heuristicScore, profileScore, matches, parsed.anomalyFlags);
    const tPol = performance.now() - tPol0;

    const totalMs = performance.now() - t0;

    return {
      eventId: "sec-" + Math.random().toString(36).slice(2, 10),
      timestamp: new Date().toISOString(),
      clientIp,
      method: parsed.method,
      path: parsed.canonicalPath,
      rawUri: parsed.rawUri,
      decision: decision.action,
      riskScore: decision.riskScore,
      confidence: decision.confidence,
      signals: {
        deterministicScore: Math.round(detScore * 1000) / 1000,
        heuristicScore: Math.round(heuristicScore * 1000) / 1000,
        profileScore: Math.round(profileScore * 1000) / 1000,
      },
      matchedRules: matches,
      anomalyFlags: parsed.anomalyFlags,
      profileContext: {
        isKnownRoute: profileEval.isKnownRoute,
        adaptationBudget: profileEval.adaptationBudget,
        reason: profileEval.reason,
      },
      decisionReason: decision.reason,
      latencies: {
        totalMs: Math.round(totalMs * 100) / 100,
        canonicalizationMs: Math.round(tCanon * 100) / 100,
        rulesMs: Math.round(tRules * 100) / 100,
        heuristicMs: Math.round(tHeuristic * 100) / 100,
        policyMs: Math.round(tPol * 100) / 100,
      },
    };
  }
}
