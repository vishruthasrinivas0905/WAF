export interface SecurityEvent {
  eventId: string;
  timestamp: string;
  clientIp: string;
  method: string;
  path: string;
  rawUri: string;
  decision: "ALLOW" | "MONITOR" | "BLOCK";
  riskScore: number;
  confidence: number;
  signals: {
    deterministicScore: number;
    transformerScore: number;
    profileScore: number;
  };
  matchedRules: {
    ruleId: string;
    category: string;
    severity: number;
    description: string;
    matchedSnippet: string;
  }[];
  anomalyFlags: string[];
  profileContext: {
    isKnownRoute: boolean;
    adaptationBudget: number;
    reason: string;
  };
  decisionReason: string;
  latencies: {
    totalMs: number;
    canonicalizationMs: number;
    rulesMs: number;
    transformerMs: number;
    policyMs: number;
  };
}

export interface WafMetrics {
  totalRequests: number;
  allowed: number;
  monitored: number;
  blocked: number;
  totalRuleMatches: number;
  p50LatencyMs: number;
  p95LatencyMs: number;
  p99LatencyMs: number;
  categoryCounts: Record<string, number>;
}
