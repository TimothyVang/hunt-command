import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, test } from "bun:test";
import { PACKAGED_RENDERER_CSP } from "../src/shared/csp.ts";
import { EventBatcher } from "../src/main/daemon/event-batcher.ts";
import { LineSplitter } from "../src/main/daemon/framing.ts";
import { buildDaemonChildEnv } from "../src/main/daemon/resolve-daemon.ts";
import { SecretVault } from "../src/main/secret-vault.ts";
import { matchesTrustedRendererUrl } from "../src/main/security.ts";
import { EVENT_CHANNELS, INVOKE_CHANNELS } from "../src/shared/ipc.ts";
import {
  defangIndicator,
  isSafeImageSrc,
  MAX_INLINE_SVG_BYTES,
  sanitizeSingleLine,
  stripControlAndBidiChars,
  tokenizeForensicText,
} from "../src/shared/sanitize.ts";

function walkFiles(dir: string): string[] {
  const out: string[] = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      out.push(...walkFiles(full));
    } else if (/\.[cm]?[jt]sx?$/.test(entry.name)) {
      out.push(full);
    }
  }
  return out;
}

describe("Desktop zero-egress security & indicator defanging (#178, #189)", () => {
  test("apps/desktop/src contains zero shell.openExternal, zero dangerouslySetInnerHTML, and zero node-pty", () => {
    const srcDir = path.resolve(import.meta.dir, "../src");
    const files = walkFiles(srcDir);
    expect(files.length).toBeGreaterThan(15);

    for (const file of files) {
      const lines = fs.readFileSync(file, "utf8").split(/\r?\n/);
      for (const line of lines) {
        const trimmed = line.trim();
        if (trimmed.startsWith("//") || trimmed.startsWith("*") || trimmed.startsWith("/*")) {
          continue;
        }
        expect(line).not.toMatch(/\bopenExternal(?:Safe)?\b/);
        expect(line).not.toMatch(/\bdangerouslySetInnerHTML\b/);
        expect(line).not.toMatch(/node-pty/);
      }
    }
  });

  test("packaged renderer CSP enforces connect-src 'none' and worker-src 'self' blob:", () => {
    expect(PACKAGED_RENDERER_CSP).toContain("default-src 'self'");
    expect(PACKAGED_RENDERER_CSP).toContain("connect-src 'none'");
    expect(PACKAGED_RENDERER_CSP).toContain("worker-src 'self' blob:");
    expect(PACKAGED_RENDERER_CSP).toContain("object-src 'none'");
    expect(PACKAGED_RENDERER_CSP).toContain("frame-ancestors 'none'");
  });

  test("preload IPC channel allowlist rejects consumer coding & external-browser channels", () => {
    expect(INVOKE_CHANNELS.has("hunt:getWorkbenchState")).toBe(true);
    expect(INVOKE_CHANNELS.has("hunt:globalStop")).toBe(true);
    expect(INVOKE_CHANNELS.has("hunt:submitGateDecision")).toBe(true);

    expect(INVOKE_CHANNELS.has("app:openExternal")).toBe(false);
    expect(INVOKE_CHANNELS.has("shell:openExternal")).toBe(false);
    expect(INVOKE_CHANNELS.has("terminal:create")).toBe(false);
    expect(INVOKE_CHANNELS.has("workspace:open")).toBe(false);
    expect(INVOKE_CHANNELS.has("mcp:connect")).toBe(false);
    expect(INVOKE_CHANNELS.has("connectors:list")).toBe(false);
    expect(EVENT_CHANNELS.has("terminal:data")).toBe(false);
  });

  test("stripControlAndBidiChars removes Unicode bidi overrides, zero-width chars, and ANSI CSI/OSC escapes", () => {
    const hostile =
      "analyst\u202Eevil\u2066isolate\u200Bzwsp\uFEFFbom \u001B[31mRED\u001B[0m \u001B]8;;https://evil.test\u0007click\u001B]8;;\u0007\x07";
    const cleaned = stripControlAndBidiChars(hostile);
    expect(cleaned).toBe("analystevilisolatezwspbom RED click");
    expect(sanitizeSingleLine("line1\n\tline2\u202E")).toBe("line1 line2");
  });

  test("defangIndicator and tokenizeForensicText defang URLs/IPs/domains while preserving evt/frame/ioc badges", () => {
    expect(defangIndicator("https://cdn-telemetry.northvale-sync.test/api/v2/checkin")).toBe(
      "hxxps://cdn-telemetry.northvale-sync[.]test/api/v2/checkin",
    );
    expect(defangIndicator("http://198.51.100.42:8443/stage")).toBe(
      "hxxp://198.51.100[.]42:8443/stage",
    );
    expect(defangIndicator("198.51.100.42")).toBe("198.51.100[.]42");
    expect(defangIndicator("beacon.evil.com")).toBe("beacon.evil[.]com");

    const sample =
      "Task (evt-0000000000001048) beaconed to https://c2.bad.org/p (frame-188, ioc-10042) via 198.51.100.42.";
    const tokens = tokenizeForensicText(sample);

    const citations = tokens.filter((t) => t.kind === "citation").map((t) => t.id);
    expect(citations).toEqual(["evt-0000000000001048", "frame-188", "ioc-10042"]);

    const indicators = tokens.filter((t) => t.kind === "indicator").map((t) => t.defanged);
    expect(indicators).toEqual(["hxxps://c2.bad[.]org/p", "198.51.100[.]42"]);
  });

  test("isSafeImageSrc blocks remote URLs, >64KiB SVG bombs, and script/filter SVG payloads", () => {
    expect(isSafeImageSrc("https://evil.com/pixel.png")).toBe(false);
    expect(isSafeImageSrc("//evil.com/pixel.png")).toBe(false);
    expect(isSafeImageSrc("./assets/logo.png")).toBe(true);

    const cleanSvg = `data:image/svg+xml;utf8,${encodeURIComponent('<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16"><circle cx="8" cy="8" r="6"/></svg>')}`;
    expect(isSafeImageSrc(cleanSvg)).toBe(true);

    const scriptSvg = `data:image/svg+xml;utf8,${encodeURIComponent('<svg><script>alert(1)</script></svg>')}`;
    expect(isSafeImageSrc(scriptSvg)).toBe(false);

    const filterBombSvg = `data:image/svg+xml;utf8,${encodeURIComponent('<svg><filter><feTurbulence type="fractalNoise"/></filter></svg>')}`;
    expect(isSafeImageSrc(filterBombSvg)).toBe(false);

    const oversizedSvg = `data:image/svg+xml;base64,${Buffer.from(`<svg>${"A".repeat(MAX_INLINE_SVG_BYTES + 128)}</svg>`).toString("base64")}`;
    expect(isSafeImageSrc(oversizedSvg)).toBe(false);
  });

  test("matchesTrustedRendererUrl enforces exact file pathname or dev origin", () => {
    const packagedUrl = new URL("file:///C:/Program%20Files/HuntCommand/resources/app.asar/out/renderer/index.html");
    expect(
      matchesTrustedRendererUrl(
        packagedUrl,
        "file:///C:/Program%20Files/HuntCommand/resources/app.asar/out/renderer/index.html?film=1",
      ),
    ).toBe(true);
    expect(matchesTrustedRendererUrl(packagedUrl, "file:///C:/Windows/System32/cmd.exe")).toBe(
      false,
    );
    expect(matchesTrustedRendererUrl(packagedUrl, "https://attacker.example/index.html")).toBe(
      false,
    );
  });

  test("buildDaemonChildEnv strips paid API keys and injects PI_NATIVES_DIR", () => {
    const dirtyEnv: NodeJS.ProcessEnv = {
      PATH: "/usr/bin",
      ANTHROPIC_API_KEY: "test-paid-key-1",
      OPENAI_API_KEY: "test-paid-key-2",
      GEMINI_API_KEY: "test-paid-key-3",
      GOOGLE_GENAI_USE_VERTEXAI: "1",
    };
    const cleaned = buildDaemonChildEnv(dirtyEnv, "C:/runtime", "C:/natives");
    expect(cleaned.ANTHROPIC_API_KEY).toBeUndefined();
    expect(cleaned.OPENAI_API_KEY).toBeUndefined();
    expect(cleaned.GEMINI_API_KEY).toBeUndefined();
    expect(cleaned.GOOGLE_GENAI_USE_VERTEXAI).toBeUndefined();
    expect(cleaned.HUNT_COMMAND_RUNTIME_DIR).toBe("C:/runtime");
    expect(cleaned.PI_NATIVES_DIR).toBe("C:/natives");
  });

  test("LineSplitter, 33ms EventBatcher, and DPAPI SecretVault uphold framing and encryption invariants", () => {
    const lines: string[] = [];
    const oversized: number[] = [];
    const splitter = new LineSplitter(
      (buf) => lines.push(buf.toString("utf8").replace(/\r$/, "")),
      (bytes) => oversized.push(bytes),
      64,
    );
    splitter.push(Buffer.from('{"id":1}\n{"id":'));
    splitter.push(Buffer.from('2}\r\n'));
    splitter.push(Buffer.from(`${"X".repeat(80)}\n{"id":3}\n`));
    splitter.end();
    expect(lines).toEqual(['{"id":1}', '{"id":2}', '{"id":3}']);
    expect(oversized.length).toBe(1);

    const batches: Array<{ huntId: string; count: number }> = [];
    const batcher = new EventBatcher((huntId, events) => {
      batches.push({ huntId, count: events.length });
    }, 33);
    batcher.push("h1", {
      hunt_id: "h1",
      seq: 1,
      ts: "2026-11-14T15:00:00Z",
      type: "gen_ai.chat.delta",
      payload: { step_id: "evidence", text: "a" },
    });
    batcher.push("h1", {
      hunt_id: "h1",
      seq: 2,
      ts: "2026-11-14T15:00:00Z",
      type: "gen_ai.chat.delta",
      payload: { step_id: "evidence", text: "ab" },
    });
    batcher.flush();
    expect(batches).toEqual([{ huntId: "h1", count: 1 }]);

    const tmpVaultDir = fs.mkdtempSync(path.join(os.tmpdir(), "hunt-vault-test-"));
    try {
      const mockDpapi = {
        isEncryptionAvailable: () => true,
        encryptString: (plain: string) => Buffer.from(`dpapi:${plain}`, "utf8"),
        decryptString: (enc: Buffer) => {
          const str = enc.toString("utf8");
          if (!str.startsWith("dpapi:")) throw new Error("corrupt");
          return str.slice("dpapi:".length);
        },
      };
      const vault = new SecretVault(tmpVaultDir, mockDpapi);
      vault.set("elastic.work_token", "opaque-work-token-value");
      expect(vault.has("elastic.work_token")).toBe(true);
      expect(vault.getDecryptedInMainOnly("elastic.work_token")).toBe("opaque-work-token-value");
      const rawDisk = fs.readFileSync(vault.file, "utf8");
      expect(rawDisk).not.toContain("opaque-work-token-value");
    } finally {
      fs.rmSync(tmpVaultDir, { recursive: true, force: true });
    }
  });
});
