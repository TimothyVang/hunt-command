/**
 * DFIR Workbench text sanitization, indicator defanging (`hxxps://`, `[.]`),
 * inline provenance tokenization (`evt-*` / `frame-*` / `ioc-*`), and `<64 KiB` SVG guard.
 *
 * Security invariants (#178 G1.1 & G1.2, ADR-0003, Rule 2):
 * - Strips Unicode bidirectional overrides/isolates, zero-width smuggling chars, and ANSI CSI/OSC escapes.
 * - Never emits clickable `http(s)://` links; converts URLs, IPv4s, and FQDNs into defanged copy-only tokens.
 * - Caps `data:image/svg+xml` payloads at <64 KiB and rejects script/filter/foreignObject vectors.
 */

// ANSI CSI (`ESC [ ... final`), OSC (`ESC ] ... BEL/ST`), and residual ESC sequences.
const ANSI_ESCAPE_RE =
  /\u001B(?:\[[0-?]*[ -/]*[@-~]|\][^\u0007\u001B]*(?:\u0007|\u001B\\)|[@-Z\\-_])/g;

// Unicode bidi controls (LRE..RLO, LRI..PDI, ALM, LRM, RLM) + zero-width/invisible formatters + soft hyphen.
const BIDI_AND_ZERO_WIDTH_RE =
  /[\u00AD\u061C\u200B-\u200F\u202A-\u202E\u2060-\u2069\uFEFF]/g;

// C0 (excluding \t=0x09 and \n=0x0A) + DEL (0x7F) + C1 (0x80..0x9F).
const C0_C1_CONTROL_RE = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F]/g;

export const MAX_INLINE_SVG_BYTES = 64 * 1024;

const DANGEROUS_SVG_VECTOR_RE =
  /<\s*(?:script|foreignObject|iframe|embed|object|feTurbulence|feDisplacementMap|feConvolveMatrix|animate|set)\b|\bon[a-z]+\s*=|(?:xlink:)?href\s*=\s*["']\s*(?:https?:|javascript:|data:text\/html|\/\/)/i;

/**
 * Strips ANSI escapes, Unicode bidi overrides/isolates, zero-width smuggling chars,
 * and C0/C1 control characters while preserving `\n` and `\t` (normalizing `\r\n` -> `\n`).
 */
export function stripControlAndBidiChars(input: string): string {
  if (input.length === 0) {
    return "";
  }
  return input
    .replace(/\r\n?/g, "\n")
    .replace(ANSI_ESCAPE_RE, "")
    .replace(BIDI_AND_ZERO_WIDTH_RE, "")
    .replace(C0_C1_CONTROL_RE, "");
}

/**
 * Single-line variant collapsing tabs/newlines into single spaces for Gate Card headers,
 * principal names, IDs, and ASS subtitle lines.
 */
export function sanitizeSingleLine(input: string): string {
  return stripControlAndBidiChars(input).replace(/[\n\t]+/g, " ").trim();
}

function defangHostPart(host: string): string {
  if (!host.includes(".") || host.includes("[.]")) {
    return host;
  }
  const lastDot = host.lastIndexOf(".");
  if (lastDot <= 0 || lastDot === host.length - 1) {
    return host;
  }
  return `${host.slice(0, lastDot)}[.]${host.slice(lastDot + 1)}`;
}

/**
 * Defangs a live URL, IPv4 address, or domain name for safe copy-only DFIR rendering:
 * - `https://c2.evil.com/a` -> `hxxps://c2.evil[.]com/a`
 * - `http://198.51.100.7:8080/p` -> `hxxp://198.51.100[.]7:8080/p`
 * - `198.51.100.7` -> `198.51.100[.]7`
 * - `beacon.northvale.test` -> `beacon.northvale[.]test`
 */
export function defangIndicator(raw: string): string {
  const cleaned = sanitizeSingleLine(raw);
  const schemeMatch = /^(https?|ftp|wss?)(:\/\/)(.*)$/i.exec(cleaned);
  if (schemeMatch) {
    const scheme = (schemeMatch[1] ?? "").toLowerCase();
    const sep = schemeMatch[2] ?? "://";
    const rest = schemeMatch[3] ?? "";
    const defangedScheme =
      scheme === "https"
        ? "hxxps"
        : scheme === "http"
          ? "hxxp"
          : scheme === "ftp"
            ? "fxp"
            : scheme === "wss"
              ? "wxss"
              : "wxs";

    const slashIdx = rest.search(/[/?#]/);
    const authority = slashIdx === -1 ? rest : rest.slice(0, slashIdx);
    const tail = slashIdx === -1 ? "" : rest.slice(slashIdx);

    // Strip any embedded user:pass@ credentials when displaying authority.
    const atIdx = authority.lastIndexOf("@");
    const hostPort = atIdx === -1 ? authority : authority.slice(atIdx + 1);
    const colonIdx = hostPort.startsWith("[") ? -1 : hostPort.lastIndexOf(":");
    const host = colonIdx > 0 ? hostPort.slice(0, colonIdx) : hostPort;
    const port = colonIdx > 0 ? hostPort.slice(colonIdx) : "";

    return `${defangedScheme}${sep}${defangHostPart(host)}${port}${tail}`;
  }

  return defangHostPart(cleaned);
}

export type CitationKind = "evt" | "frame" | "ioc";
export type IndicatorKind = "url" | "ipv4" | "domain";

export type ForensicTextToken =
  | { readonly kind: "text"; readonly text: string }
  | {
      readonly kind: "citation";
      readonly id: string;
      readonly citationKind: CitationKind;
    }
  | {
      readonly kind: "indicator";
      readonly raw: string;
      readonly defanged: string;
      readonly indicatorKind: IndicatorKind;
    };

// Non-domain token rules, tried in this order at each position (an earlier rule wins a tie):
// 1: Citation (`evt-*`, `frame-\d+`, `ioc-\d+`)
// 2: Explicit URL (`https?://...`, `hxxps?://...`, `ftp://...`, `wss?://...`)
// 3: Standalone IPv4 (`a.b.c.d` with optional `:port`)
// All three are linear: the IPv4 rule is bounded, and the citation and URL rules start only at a word
// boundary and consume their whole token. Case-insensitive because schemes and hostnames are, so
// `HTTPS://EVIL.EXAMPLE/Y` and `hTtP://Evil.Example/y` are defanged like their lowercase forms.
const NON_DOMAIN_TOKEN_RE = new RegExp(
  [
    "(\\b(?:evt-[A-Za-z0-9_-]+|frame-\\d+|ioc-\\d+)\\b)",
    "(\\b(?:https?|hxxps?|ftp|fxp|wss?|wxss?):\\/\\/[^\\s<>\"'`\\])]+)",
    "(\\b(?:(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)\\.){3}(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)(?::\\d{1,5})?\\b)",
  ].join("|"),
  "gi",
);

const CITATION_ID_RE = /^(?:evt-[A-Za-z0-9_-]+|frame-\d+|ioc-\d+)$/;

// 4: Standalone FQDN with common DFIR/enterprise/lab TLDs (avoiding ECS dotted field names like
//    `process.command_line`). Semantically this is exactly the case-insensitive rule
//      \b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:<DOMAIN_TLDS>)\b
//    but `findDomainMatches` evaluates it in linear time. As a regex, every label start inside a long
//    dotted run (`a.a.a.…`, `www.www.…`) re-scanned the rest of the run before failing, which made long
//    untrusted inputs quadratic (about 14 s for 200 KB).
export const DOMAIN_TLDS: ReadonlySet<string> = new Set([
  "com", "net", "org", "io", "dev", "app", "cloud", "gov", "mil", "edu", "info", "biz", "xyz", "top",
  "ru", "cn", "ir", "kp", "uk", "de", "fr", "nl", "co", "me", "ai", "test", "example", "invalid",
  "localhost", "local", "internal", "corp", "lan",
]);

const DOMAIN_RUN_RE = /[A-Za-z0-9_.-]+/g;
const MAX_LABEL_LENGTH = 63;

function isAsciiAlnum(code: number): boolean {
  return (code >= 48 && code <= 57) || (code >= 65 && code <= 90) || (code >= 97 && code <= 122);
}

/**
 * Every match of the FQDN rule as `[start, end)`, sorted by start, one entry per possible start.
 *
 * A match starting at `q` depends only on `q` (word boundaries look at the real text, not at the scan
 * cursor), so every match can be computed up front in one pass over each run of `[A-Za-z0-9_.-]`:
 * - The run splits on `.` into segments. Labels are whole segments, except that the first label may be
 *   the suffix of a segment that starts after a `-`. A label is 1-63 chars of `[A-Za-z0-9-]` with an
 *   alphanumeric first and last char, and is followed by `.`.
 * - A TLD matches at segment `j` when the segment's text up to its first `-` is a listed TLD. This is the
 *   trailing `\b`: `-`, `.`, and every character outside the run are non-word, `_` is a word char.
 * - From a first label in segment `k`, greedy `(label\.)+` with backtracking ends at the LAST TLD match
 *   reachable through consecutive valid labels after `k`. `best[j]` stores that, computed backwards, so
 *   each run costs O(length).
 */
export function findDomainMatches(text: string): Array<readonly [number, number]> {
  const matches: Array<readonly [number, number]> = [];
  const runRe = new RegExp(DOMAIN_RUN_RE.source, "g");
  let run: RegExpExecArray | null;
  while ((run = runRe.exec(text)) !== null) {
    const runStart = run.index;
    const runText = run[0];
    if (!runText.includes(".")) continue;

    const segStarts: number[] = [];
    const segEnds: number[] = [];
    let segStart = 0;
    for (let i = 0; i <= runText.length; i++) {
      if (i === runText.length || runText.charCodeAt(i) === 46) {
        segStarts.push(segStart);
        segEnds.push(i);
        segStart = i + 1;
      }
    }
    const lastIdx = segStarts.length - 1;

    const tldLen: number[] = [];
    const valid: boolean[] = [];
    for (let j = 0; j <= lastIdx; j++) {
      const a = segStarts[j]!;
      const b = segEnds[j]!;
      const seg = runText.slice(a, b);
      const hyphen = seg.indexOf("-");
      const word = (hyphen === -1 ? seg : seg.slice(0, hyphen)).toLowerCase();
      tldLen.push(DOMAIN_TLDS.has(word) ? word.length : 0);
      valid.push(
        b - a >= 1 &&
          b - a <= MAX_LABEL_LENGTH &&
          isAsciiAlnum(runText.charCodeAt(a)) &&
          isAsciiAlnum(runText.charCodeAt(b - 1)) &&
          !seg.includes("_"),
      );
    }

    // best[j]: index of the last TLD match reachable from segment j (inclusive), or -1.
    const best: number[] = new Array<number>(lastIdx + 1).fill(-1);
    for (let j = lastIdx; j >= 0; j--) {
      const viaLabel = valid[j] && j < lastIdx ? best[j + 1]! : -1;
      best[j] = viaLabel !== -1 ? viaLabel : tldLen[j]! > 0 ? j : -1;
    }

    for (let k = 0; k < lastIdx; k++) {
      const target = best[k + 1]!;
      if (target === -1) continue;
      const a = segStarts[k]!;
      const b = segEnds[k]!;
      if (b === a || !isAsciiAlnum(runText.charCodeAt(b - 1))) continue;
      // The first label is a suffix of this segment: skip past its last `_` (search the segment only).
      const underscore = runText.slice(a, b).lastIndexOf("_");
      const lo = Math.max(a, b - MAX_LABEL_LENGTH, underscore >= 0 ? a + underscore + 1 : a);
      const end = runStart + segStarts[target]! + tldLen[target]!;
      for (let q = lo; q < b; q++) {
        const isStart = q === a || runText.charCodeAt(q - 1) === 45;
        if (isStart && isAsciiAlnum(runText.charCodeAt(q))) {
          matches.push([runStart + q, end]);
        }
      }
    }
  }
  return matches;
}

function trimTrailingPunctuation(token: string): { core: string; trailing: string } {
  let end = token.length;
  while (end > 0) {
    const ch = token[end - 1];
    if (ch === "." || ch === "," || ch === ";" || ch === ":" || ch === "!" || ch === "?") {
      end--;
    } else if (ch === ")" && !token.slice(0, end).includes("(")) {
      end--;
    } else {
      break;
    }
  }
  return { core: token.slice(0, end), trailing: token.slice(end) };
}

/**
 * Tokenizes untrusted model/telemetry text into safe React text nodes,
 * interactive provenance citation chips, and defanged copy-only indicator pills.
 */
export function tokenizeForensicText(rawInput: string): ForensicTextToken[] {
  const cleaned = stripControlAndBidiChars(rawInput);
  if (cleaned.length === 0) {
    return [];
  }

  const tokens: ForensicTextToken[] = [];
  let cursor = 0;

  const pushText = (segment: string) => {
    if (segment.length === 0) return;
    const prev = tokens[tokens.length - 1];
    if (prev && prev.kind === "text") {
      tokens[tokens.length - 1] = { kind: "text", text: prev.text + segment };
    } else {
      tokens.push({ kind: "text", text: segment });
    }
  };

  // Leftmost token wins; on a tie the non-domain rules win (they precede the FQDN rule). Both sources only
  // move forward, and a pending regex match is reused until the cursor passes it, so the scan is linear.
  const domains = findDomainMatches(cleaned);
  let domainIdx = 0;
  let pending: RegExpExecArray | null | undefined;
  for (;;) {
    if (pending === undefined || (pending !== null && pending.index < cursor)) {
      NON_DOMAIN_TOKEN_RE.lastIndex = cursor;
      pending = NON_DOMAIN_TOKEN_RE.exec(cleaned);
    }
    while (domainIdx < domains.length && domains[domainIdx]![0] < cursor) domainIdx++;
    const domain = domains[domainIdx];
    let match: { index: number; 0: string; 1?: string; 2?: string; 3?: string };
    if (pending !== null && (domain === undefined || pending.index <= domain[0])) {
      match = pending;
      pending = undefined;
    } else if (domain !== undefined) {
      match = { index: domain[0], 0: cleaned.slice(domain[0], domain[1]) };
    } else {
      break;
    }

    const matchIndex = match.index;
    if (matchIndex > cursor) {
      pushText(cleaned.slice(cursor, matchIndex));
    }

    const fullMatch = match[0];
    if (match[1] !== undefined && CITATION_ID_RE.test(match[1])) {
      const id = match[1];
      const citationKind: CitationKind = id.startsWith("evt-")
        ? "evt"
        : id.startsWith("frame-")
          ? "frame"
          : "ioc";
      tokens.push({ kind: "citation", id, citationKind });
      cursor = matchIndex + fullMatch.length;
      continue;
    }

    if (match[1] !== undefined) {
      // Upper/mixed-case `EVT-*` etc. is not a provenance citation; keep it as plain text.
      pushText(fullMatch);
      cursor = matchIndex + fullMatch.length;
      continue;
    }

    const { core, trailing } = trimTrailingPunctuation(fullMatch);
    if (core.length === 0) {
      pushText(fullMatch);
      cursor = matchIndex + fullMatch.length;
      continue;
    }

    const indicatorKind: IndicatorKind =
      match[2] !== undefined ? "url" : match[3] !== undefined ? "ipv4" : "domain";

    tokens.push({
      kind: "indicator",
      raw: core,
      defanged: defangIndicator(core),
      indicatorKind,
    });
    if (trailing.length > 0) {
      pushText(trailing);
    }
    cursor = matchIndex + fullMatch.length;
  }

  if (cursor < cleaned.length) {
    pushText(cleaned.slice(cursor));
  }

  return tokens;
}

/**
 * Validates image sources in the renderer (`#178` G1.2):
 * - Blocks all remote `http:` / `https:` / `ws:` / protocol-relative URLs.
 * - Allows local relative assets, `blob:`, and raster `data:image/(png|jpeg|gif|webp);base64,...`.
 * - Enforces `<64 KiB` (`65,536` bytes) cap and blocks dangerous tags/attributes on `data:image/svg+xml`.
 */
export function isSafeImageSrc(src: string): boolean {
  const trimmed = src.trim();
  if (trimmed.length === 0) {
    return false;
  }
  if (/^(?:https?:|wss?:|ftp:|file:|javascript:|vbscript:|\/\/)/i.test(trimmed)) {
    return false;
  }
  if (trimmed.startsWith("blob:")) {
    return true;
  }
  if (trimmed.startsWith("data:")) {
    if (/^data:image\/(?:png|jpeg|jpg|webp|gif);base64,[A-Za-z0-9+/=]+$/i.test(trimmed)) {
      return new TextEncoder().encode(trimmed).byteLength <= 4 * 1024 * 1024;
    }
    if (/^data:image\/svg\+xml[;,]/i.test(trimmed)) {
      const byteLen = new TextEncoder().encode(trimmed).byteLength;
      if (byteLen >= MAX_INLINE_SVG_BYTES) {
        return false;
      }
      const commaIdx = trimmed.indexOf(",");
      if (commaIdx === -1) {
        return false;
      }
      const header = trimmed.slice(0, commaIdx).toLowerCase();
      const rawPayload = trimmed.slice(commaIdx + 1);
      let decodedSvg: string;
      try {
        if (header.includes(";base64")) {
          decodedSvg = atob(rawPayload);
        } else {
          decodedSvg = decodeURIComponent(rawPayload);
        }
      } catch {
        return false;
      }
      if (new TextEncoder().encode(decodedSvg).byteLength >= MAX_INLINE_SVG_BYTES) {
        return false;
      }
      if (DANGEROUS_SVG_VECTOR_RE.test(decodedSvg)) {
        return false;
      }
      return true;
    }
    return false;
  }

  // Relative same-origin path (e.g. `./assets/...` or `/assets/...`, never `//`)
  return /^[./A-Za-z0-9_-][A-Za-z0-9_./-]*$/.test(trimmed);
}
