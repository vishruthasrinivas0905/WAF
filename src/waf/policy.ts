import { RuleMatch } from "./rules.ts";

export interface DecisionResult {
  action: "ALLOW" | "MONITOR" | "BLOCK";
  riskScore: number;
  confidence: number;
  reason: string;
}

export class PolicyEngine {
  public mode: "ENFORCING" | "MONITORING" | "SIMULATION";
  public blockThreshold: number;
  public monitorThreshold: number;
  public wDet: number;
  public wMl: number;
  public wApp: number;

  constructor(options?: {
    mode?: "ENFORCING" | "MONITORING" | "SIMULATION";
    blockThreshold?: number;
    monitorThreshold?: number;
    wDet?: number;
    wMl?: number;
    wApp?: number;
  }) {
    this.mode = options?.mode || "ENFORCING";
    this.blockThreshold = options?.blockThreshold ?? 0.7;
    this.monitorThreshold = options?.monitorThreshold ?? 0.4;
    this.wDet = options?.wDet ?? 0.45;
    this.wMl = options?.wMl ?? 0.4;
    this.wApp = options?.wApp ?? 0.15;
  }

  public evaluate(
    detScore: number,
    mlScore: number,
    appScore: number,
    ruleMatches: RuleMatch[],
    anomalyFlags: string[]
  ): DecisionResult {
    // 1. Critical Deterministic Rule Override
    const hasCriticalAttackRule = ruleMatches.some((r) =>
      ["SQLI", "XSS", "RCE", "TRAVERSAL"].includes(r.category) || r.severity >= 4
    );
    if (detScore >= 0.85 || hasCriticalAttackRule) {
      const topRule = ruleMatches[0]?.ruleId || "CRS_SIG";
      const action = this.mode === "ENFORCING" ? "BLOCK" : "MONITOR";
      return {
        action,
        riskScore: Math.max(detScore, 0.9),
        confidence: 0.98,
        reason: `High-confidence deterministic rule match: ${topRule} (${ruleMatches[0]?.description || "Malicious Payload"})`,
      };
    }

    // 2. Multi-Signal Fusion
    let risk = this.wDet * detScore + this.wMl * mlScore + this.wApp * appScore;

    // 3. Application-Aware False Positive Suppression
    if (detScore === 0 && appScore === 0 && mlScore >= 0.35 && mlScore <= 0.65) {
      risk *= 0.65; // Contextual attenuation
    }

    // 4. Evasion flag penalty
    if (anomalyFlags.some((f) => f.includes("DOUBLE_URL") || f.includes("NULL_BYTE"))) {
      risk = Math.min(1.0, risk + 0.2);
    }

    // 5. Threshold Enforcement
    let action: "ALLOW" | "MONITOR" | "BLOCK" = "ALLOW";
    let reason = "Clean request within safe risk tolerance";

    if (risk >= this.blockThreshold) {
      action = this.mode === "ENFORCING" ? "BLOCK" : "MONITOR";
      reason = `Risk score (${risk.toFixed(2)}) exceeds block threshold (${this.blockThreshold})`;
    } else if (risk >= this.monitorThreshold) {
      action = "MONITOR";
      reason = `Moderate risk score (${risk.toFixed(2)}) flagged for security audit`;
    }

    const confidence = 1.0 - Math.abs(risk - 0.5) * 0.5;

    return {
      action,
      riskScore: Math.round(risk * 10000) / 10000,
      confidence: Math.round(confidence * 10000) / 10000,
      reason,
    };
  }
}
