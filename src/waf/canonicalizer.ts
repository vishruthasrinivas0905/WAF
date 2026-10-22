// Request Normalizer & Defensive Canonicalizer in TypeScript

const DATASET_ARTIFACT_REGEX = /(\n|\r\n)*(null\s*)?(End\s*-\s*Id:.*|Start\s*-\s*Id:.*|class:\s*(Valid|Anomaly)).*$/is;
const VALID_METHODS = new Set(["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]);

export interface ParsedRequest {
  method: string;
  rawUri: string;
  canonicalPath: string;
  queryString: string;
  queryParams: Record<string, string>;
  headers: Record<string, string>;
  body: string;
  httpVersion: string;
  anomalyFlags: string[];
  canonicalText: string;
}

export function stripDatasetArtifacts(text: string): string {
  if (!text) return "";
  return text.replace(DATASET_ARTIFACT_REGEX, "").trimEnd();
}

export function safeUrlDecode(input: string, maxPasses = 3): { text: string; passes: number } {
  if (!input) return { text: "", passes: 0 };
  let current = input;
  let passes = 0;
  for (let i = 0; i < maxPasses; i++) {
    try {
      const decoded = decodeURIComponent(current.replace(/\+/g, " "));
      if (decoded === current) break;
      current = decoded;
      passes++;
    } catch {
      break;
    }
  }
  return { text: current, passes };
}

export function normalizePath(path: string): string {
  if (!path) return "/";
  // Replace multiple consecutive slashes
  let p = path.replace(/\/+/g, "/");
  const segments = p.split("/");
  const resolved: string[] = [];
  for (const seg of segments) {
    if (seg === "" || seg === ".") continue;
    if (seg === "..") {
      if (resolved.length > 0) resolved.pop();
    } else {
      resolved.push(seg);
    }
  }
  return "/" + resolved.join("/");
}

export function parseHttpRequest(rawRequest: string): ParsedRequest {
  const anomalyFlags: string[] = [];
  let cleaned = stripDatasetArtifacts(rawRequest);

  if (cleaned.includes("\x00") || cleaned.toLowerCase().includes("%00")) {
    anomalyFlags.push("NULL_BYTE_DETECTED");
    cleaned = cleaned.replace(/\x00/g, "").replace(/%00/gi, "");
  }

  const lines = cleaned.split(/\r?\n/);
  if (!lines.length || !lines[0].trim()) {
    return {
      method: "UNKNOWN",
      rawUri: "/",
      canonicalPath: "/",
      queryString: "",
      queryParams: {},
      headers: {},
      body: "",
      httpVersion: "HTTP/1.1",
      anomalyFlags: ["EMPTY_REQUEST"],
      canonicalText: "",
    };
  }

  const firstLine = lines[0].trim();
  const parts = firstLine.split(/\s+/);
  let method = "GET";
  let rawUri = "/";
  let httpVersion = "HTTP/1.1";

  if (parts.length >= 2 && VALID_METHODS.has(parts[0].toUpperCase())) {
    method = parts[0].toUpperCase();
    if (/^HTTP\/\d\.\d$/i.test(parts[parts.length - 1])) {
      httpVersion = parts[parts.length - 1].toUpperCase();
      rawUri = parts.slice(1, -1).join(" ");
    } else {
      rawUri = parts.slice(1).join(" ");
    }
  } else {
    rawUri = firstLine;
  }

  // Parse headers and body
  const headers: Record<string, string> = {};
  const bodyLines: string[] = [];
  let readingHeaders = true;

  for (let i = 1; i < lines.length; i++) {
    const line = lines[i];
    if (readingHeaders) {
      if (!line.trim()) {
        readingHeaders = false;
        continue;
      }
      const colonIdx = line.indexOf(":");
      if (colonIdx > 0) {
        const k = line.slice(0, colonIdx).trim().toLowerCase();
        const v = line.slice(colonIdx + 1).trim();
        headers[k] = v;
      }
    } else {
      bodyLines.push(line);
    }
  }

  const rawBody = bodyLines.join("\n").trim();

  // Parse URI, Path, and Query
  let path = rawUri;
  let query = "";
  const qIdx = rawUri.indexOf("?");
  if (qIdx >= 0) {
    path = rawUri.slice(0, qIdx);
    query = rawUri.slice(qIdx + 1);
  }

  const { text: decodedPath, passes: pathPasses } = safeUrlDecode(path);
  if (pathPasses > 1) {
    anomalyFlags.push(`DOUBLE_URL_ENCODED_PATH_${pathPasses}X`);
  }
  const canonicalPath = normalizePath(decodedPath);

  const { text: decodedQuery, passes: queryPasses } = safeUrlDecode(query);
  if (queryPasses > 1) {
    anomalyFlags.push(`DOUBLE_URL_ENCODED_QUERY_${queryPasses}X`);
  }

  const queryParams: Record<string, string> = {};
  if (decodedQuery) {
    const pairs = decodedQuery.split("&");
    for (const pair of pairs) {
      if (!pair) continue;
      const eqIdx = pair.indexOf("=");
      if (eqIdx >= 0) {
        queryParams[pair.slice(0, eqIdx)] = pair.slice(eqIdx + 1);
      } else {
        queryParams[pair] = "";
      }
    }
  }

  const { text: decodedBody, passes: bodyPasses } = safeUrlDecode(rawBody);
  if (bodyPasses > 1) {
    anomalyFlags.push(`DOUBLE_URL_ENCODED_BODY_${bodyPasses}X`);
  }

  let canonicalText = `${method} ${canonicalPath}`;
  if (decodedQuery) canonicalText += `?${decodedQuery}`;
  if (decodedBody) canonicalText += `\nBody: ${decodedBody}`;

  return {
    method,
    rawUri,
    canonicalPath,
    queryString: decodedQuery,
    queryParams,
    headers,
    body: decodedBody,
    httpVersion,
    anomalyFlags,
    canonicalText,
  };
}
