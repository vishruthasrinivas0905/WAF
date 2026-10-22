import { ParsedRequest } from "./canonicalizer.ts";

export interface RuleDefinition {
  id: string;
  category: "SQLI" | "XSS" | "RCE" | "TRAVERSAL" | "SCANNER";
  severity: number; // 1 to 5
  desc: string;
  pattern: RegExp;
}

export interface RuleMatch {
  ruleId: string;
  category: string;
  severity: number;
  description: string;
  matchedSnippet: string;
}

export const OWASP_RULES: RuleDefinition[] = [
  // SQL Injection (CRS 942)
  {
    id: "CRS-942-100",
    category: "SQLI",
    severity: 5,
    desc: "Classic SQL comment or tautology bypass (OR 1=1, AND 1=1, --)",
    pattern: /(\b(or|and)\b\s+['"]?\w+['"]?\s*=\s*['"]?\w+|--|\/\*.*?\*\/|;\s*--|#)/i,
  },
  {
    id: "CRS-942-110",
    category: "SQLI",
    severity: 5,
    desc: "SQL UNION SELECT injection attempt",
    pattern: /\bunion(\s+all)?\s+select\b/i,
  },
  {
    id: "CRS-942-115",
    category: "SQLI",
    severity: 5,
    desc: "SQL subquery or data extraction (SELECT ... FROM ...)",
    pattern: /\bselect\b\s+[\w\*,\s\(\)]+\s+\bfrom\b/i,
  },
  {
    id: "CRS-942-120",
    category: "SQLI",
    severity: 5,
    desc: "SQL information schema or administrative table extraction",
    pattern: /\b(information_schema|syscat|pg_catalog|sqlite_master|sysobjects)\b/i,
  },
  {
    id: "CRS-942-130",
    category: "SQLI",
    severity: 5,
    desc: "SQL time-based or error-based functions (sleep, benchmark, waitfor delay)",
    pattern: /\b(sleep\s*\(\s*\d+\s*\)|benchmark\s*\(|waitfor\s+delay|pg_sleep)\b/i,
  },
  {
    id: "CRS-942-140",
    category: "SQLI",
    severity: 5,
    desc: "Dangerous stacked SQL commands (DROP, TRUNCATE, ALTER, xp_cmdshell)",
    pattern: /;\s*(drop|truncate|alter|grant|revoke)\s+\w+|\bxp_cmdshell\b/i,
  },

  // Cross-Site Scripting (CRS 941)
  {
    id: "CRS-941-100",
    category: "XSS",
    severity: 5,
    desc: "Standard script tag injection (<script>...</script>)",
    pattern: /<\s*script[^>]*>.*?<\s*\/\s*script\s*>/is,
  },
  {
    id: "CRS-941-110",
    category: "XSS",
    severity: 5,
    desc: "HTML tag with JavaScript event handler (onload, onerror, onclick)",
    pattern: /<\s*\w+[^>]+(on\w+)\s*=\s*['"].*?['"]/i,
  },
  {
    id: "CRS-941-120",
    category: "XSS",
    severity: 5,
    desc: "JavaScript pseudoprotocol URI (javascript:, vbscript:, data:text/html)",
    pattern: /\b(javascript|vbscript|data\s*:\s*text\/html)\s*:/i,
  },
  {
    id: "CRS-941-130",
    category: "XSS",
    severity: 5,
    desc: "Unclosed vector payload (<script, <svg/onload, <img src=x onerror)",
    pattern: /<\s*(script|iframe|svg|img|body|input)[^>]*(onerror|onload|onclick)/i,
  },

  // Remote Code Execution (CRS 932)
  {
    id: "CRS-932-100",
    category: "RCE",
    severity: 5,
    desc: "Unix/Linux command execution via shell chaining (| , ;, &&, $(cmd), `cmd`)",
    pattern: /(;|\||&&|\$\(|\`)\s*(cat|ls|pwd|whoami|id|uname|nc|bash|sh|curl|wget)\b/i,
  },
  {
    id: "CRS-932-105",
    category: "RCE",
    severity: 5,
    desc: "Shell invocation or reverse shell syntax (/bin/sh, nc -e, dev/tcp)",
    pattern: /(\/bin\/(ba)?sh|\bnc\s+-[el]|\/dev\/tcp\/\d|\bcmd\.exe|\bpowershell)\b/i,
  },
  {
    id: "CRS-932-110",
    category: "RCE",
    severity: 5,
    desc: "Windows cmd/powershell execution attempt",
    pattern: /\b(powershell(\.exe)?|cmd(\.exe)?)\s+-[ecenopw]+\b|\b(certutil|bitsadmin)\b/i,
  },
  {
    id: "CRS-932-120",
    category: "RCE",
    severity: 5,
    desc: "PHP code evaluation injection (eval, assert, passthru, system)",
    pattern: /\b(eval|assert|passthru|shell_exec|system|exec|proc_open)\s*\(/i,
  },
  {
    id: "CRS-932-130",
    category: "RCE",
    severity: 5,
    desc: "Java JNDI / Log4j / SSTI expression injection (${jndi:, #{...})",
    pattern: /\$\{\s*(jndi|ctx|env|sys):|#\{\s*[\w\.]+|__proto__|constructor\.prototype/i,
  },

  // Path Traversal / LFI (CRS 930)
  {
    id: "CRS-930-100",
    category: "TRAVERSAL",
    severity: 5,
    desc: "Directory traversal sequence (../ or ..\\ or encoded %2e%2e)",
    pattern: /(\.\.\/|\.\.\\|%2e%2e%2f|%2e%2e\/|\.\.%2f)/i,
  },
  {
    id: "CRS-930-110",
    category: "TRAVERSAL",
    severity: 5,
    desc: "Attempted access to known sensitive OS configuration files (/etc/passwd, win.ini)",
    pattern: /(\/etc\/(passwd|shadow|hosts|issue)|windows[\/\\]win\.ini|boot\.ini)/i,
  },

  // Scanner Probes (CRS 913)
  {
    id: "CRS-913-100",
    category: "SCANNER",
    severity: 3,
    desc: "Known vulnerability scanner or crawler signature (sqlmap, nikto, acunetix)",
    pattern: /\b(sqlmap|nikto|acunetix|nessus|nmap|dirbuster|gobuster|wpscan)\b/i,
  },
];

export function inspectDeterministicRules(parsed: ParsedRequest): {
  score: number;
  matches: RuleMatch[];
} {
  const matches: RuleMatch[] = [];
  const targets: [string, string][] = [
    ["URI", parsed.rawUri],
    ["PATH", parsed.canonicalPath],
    ["QUERY", parsed.queryString],
    ["BODY", parsed.body],
    ["TEXT", parsed.canonicalText],
  ];

  for (const [k, v] of Object.entries(parsed.headers)) {
    if (["user-agent", "referer", "cookie", "x-forwarded-for"].includes(k)) {
      targets.push([`HEADER_${k.toUpperCase()}`, v]);
    }
  }

  const matchedRuleIds = new Set<string>();

  for (const rule of OWASP_RULES) {
    for (const [targetName, content] of targets) {
      if (!content) continue;
      const m = content.match(rule.pattern);
      if (m && !matchedRuleIds.has(rule.id)) {
        matchedRuleIds.add(rule.id);
        matches.push({
          ruleId: rule.id,
          category: rule.category,
          severity: rule.severity,
          description: rule.desc,
          matchedSnippet: `[${targetName}] ${m[0].slice(0, 75)}`,
        });
        break;
      }
    }
  }

  if (!matches.length) return { score: 0.0, matches: [] };

  const maxSev = Math.max(...matches.map((m) => m.severity));
  let score = 0.0;
  if (maxSev >= 5) {
    score = Math.min(1.0, 0.85 + 0.05 * (matches.length - 1));
  } else if (maxSev === 4) {
    score = Math.min(0.95, 0.65 + 0.1 * (matches.length - 1));
  } else {
    score = Math.min(0.7, 0.25 * matches.length);
  }

  return { score, matches };
}
