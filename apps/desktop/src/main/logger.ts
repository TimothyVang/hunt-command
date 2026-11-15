/**
 * Adapted from omp-desktop/app/src/main/logger.ts
 * Copyright (c) omp-desktop contributors (MIT License — see root THIRD-PARTY-NOTICES.md).
 * Modified for Hunt Command v2: strips control/bidi chars from log lines and logs
 * strictly lifecycle metadata (never case queries, claims, OAuth tokens, or secrets).
 */
import { appendFileSync, mkdirSync, renameSync, statSync } from "node:fs";
import path from "node:path";
import { sanitizeSingleLine } from "../shared/sanitize.ts";

export interface Logger {
  info(message: string): void;
  warn(message: string): void;
  error(message: string): void;
  child(scope: string): Logger;
}

const MAX_BYTES = 1024 * 1024;

export function createLogger(dir: string, scope = "main"): Logger {
  mkdirSync(dir, { recursive: true });
  const file = path.join(dir, "hunt-desktop.log");
  const write = (level: string, s: string, message: string) => {
    const line = `${new Date().toISOString()} ${level} [${s}] ${sanitizeSingleLine(message)}\n`;
    if (level !== "INFO" || process.env.HUNT_COMMAND_DEBUG === "1") {
      process.stderr.write(line);
    }
    try {
      if ((statSync(file, { throwIfNoEntry: false })?.size ?? 0) > MAX_BYTES) {
        renameSync(file, `${file}.1`);
      }
      appendFileSync(file, line, { encoding: "utf8" });
    } catch {
      // Diagnostic logging must never crash the workbench.
    }
  };

  const make = (s: string): Logger => ({
    info: (m) => write("INFO", s, m),
    warn: (m) => write("WARN", s, m),
    error: (m) => write("ERROR", s, m),
    child: (c) => make(`${s}:${c}`),
  });
  return make(scope);
}
