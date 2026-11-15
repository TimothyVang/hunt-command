import http from "node:http";
import type { DataOrigin } from "@hunt-command/shared";
import { scrubSecretsValue } from "./scrubber.ts";
import type { TelemetrySpanRecord } from "./telemetry-store.ts";

/**
 * Raw literal check BEFORE `new URL()` so WHATWG URL canonicalization of octal (`0177.0.0.1`),
 * hex (`0x7f000001`), integer (`2130706433`), or IPv4-mapped IPv6 (`[::ffff:127.0.0.1]`)
 * cannot smuggle parser differentials past `parsed.hostname === "127.0.0.1"`.
 */
const RAW_LOOPBACK_OTLP_URL_RE =
  /^http:\/\/(127\.0\.0\.1|\[::1\]):([1-9][0-9]{0,4})(\/[^\s?#]*)?$/;

export class OtlpExportError extends Error {
  public readonly errorCode: string;

  constructor(errorCode: string, message: string) {
    super(message);
    this.name = "OtlpExportError";
    this.errorCode = errorCode;
  }
}

export interface ValidateOtlpUrlOptions {
  internalBoundPorts?: Iterable<number>;
}

export interface ValidatedOtlpTarget {
  url: URL;
  hostname: "127.0.0.1" | "::1";
  urlHostname: "127.0.0.1" | "[::1]";
  port: number;
  pathname: string;
}

export interface ExportOtlpLoopbackOptions {
  endpoint: string;
  spans: readonly TelemetrySpanRecord[];
  syntheticOnly: boolean;
  dataOrigin?: DataOrigin;
  allowLocalOtlpOnWorkData?: boolean;
  internalBoundPorts?: Iterable<number>;
  timeoutMs?: number;
  serviceName?: string;
  /**
   * Optional custom fetch implementation for unit tests; when omitted, uses direct
   * proxy-immune `node:http` loopback socket transport (which ignores `HTTP_PROXY` /
   * `ALL_PROXY` even on Bun 1.4.4 Windows where `fetch({ proxy: "" })` still consults env proxies)
   * AND verifies `socket.remoteAddress` before writing body bytes.
   */
  fetchImpl?: (url: string, init: RequestInit & { proxy?: string }) => Promise<Response>;
}

export interface ExportOtlpResult {
  exported: boolean;
  skippedReason?: "work_data_otlp_disabled";
  exportedSpanCount: number;
  statusCode?: number;
}

export function validateOtlpLoopbackUrl(
  rawEndpoint: string,
  options: ValidateOtlpUrlOptions = {},
): ValidatedOtlpTarget {
  if (typeof rawEndpoint !== "string" || rawEndpoint.length === 0 || rawEndpoint.length > 512) {
    throw new OtlpExportError("invalid_otlp_endpoint", "OTLP endpoint must be a non-empty URL");
  }

  for (let i = 0; i < rawEndpoint.length; i++) {
    const code = rawEndpoint.charCodeAt(i);
    if (code <= 0x20 || code >= 0x7f) {
      throw new OtlpExportError(
        "invalid_otlp_endpoint",
        "OTLP endpoint contains whitespace or non-ASCII control characters",
      );
    }
  }

  const rawMatch = RAW_LOOPBACK_OTLP_URL_RE.exec(rawEndpoint);
  if (!rawMatch) {
    throw new OtlpExportError(
      "otlp_non_loopback_rejected",
      "OTLP endpoint must use literal http://127.0.0.1:<port> or http://[::1]:<port> without userinfo, query, fragment, localhost, or non-decimal IP encodings",
    );
  }

  let parsed: URL;
  try {
    parsed = new URL(rawEndpoint);
  } catch {
    throw new OtlpExportError("invalid_otlp_endpoint", "Malformed OTLP URL");
  }

  if (parsed.protocol !== "http:") {
    throw new OtlpExportError("otlp_protocol_rejected", "OTLP loopback endpoint must use http:");
  }

  if (parsed.username !== "" || parsed.password !== "") {
    throw new OtlpExportError(
      "otlp_userinfo_rejected",
      "OTLP loopback endpoint must not contain URL credentials",
    );
  }

  if (parsed.search !== "" || parsed.hash !== "") {
    throw new OtlpExportError(
      "otlp_query_or_hash_rejected",
      "OTLP loopback endpoint must not contain query parameters or fragments",
    );
  }

  if (parsed.hostname !== "127.0.0.1" && parsed.hostname !== "[::1]") {
    throw new OtlpExportError(
      "otlp_non_loopback_rejected",
      `OTLP hostname '${parsed.hostname}' is not literal 127.0.0.1 or [::1]`,
    );
  }

  if (!/^[1-9][0-9]{0,4}$/.test(parsed.port)) {
    throw new OtlpExportError("otlp_port_rejected", "OTLP endpoint must specify an explicit port");
  }

  const port = Number(parsed.port);
  if (!Number.isInteger(port) || port < 1024 || port > 65535) {
    throw new OtlpExportError(
      "otlp_port_rejected",
      `OTLP port ${port} must be an unprivileged loopback port in 1024..65535`,
    );
  }

  if (options.internalBoundPorts) {
    for (const bound of options.internalBoundPorts) {
      if (bound === port) {
        throw new OtlpExportError(
          "otlp_internal_port_rejected",
          `OTLP port ${port} collides with an internal Hunt Command bound port`,
        );
      }
    }
  }

  const pathname = parsed.pathname && parsed.pathname !== "/" ? parsed.pathname : "/v1/traces";
  parsed.pathname = pathname;

  return {
    url: parsed,
    hostname: parsed.hostname === "[::1]" ? "::1" : "127.0.0.1",
    urlHostname: parsed.hostname,
    port,
    pathname,
  };
}

function toOtlpAttributeValue(value: unknown): Record<string, unknown> {
  if (typeof value === "string") {
    return { stringValue: value };
  }
  if (typeof value === "boolean") {
    return { boolValue: value };
  }
  if (typeof value === "number") {
    return Number.isInteger(value) ? { intValue: String(value) } : { doubleValue: value };
  }
  if (Array.isArray(value)) {
    return {
      arrayValue: {
        values: value.map((item) => toOtlpAttributeValue(item)),
      },
    };
  }
  return { stringValue: JSON.stringify(value) };
}

export function buildOtlpTracesPayload(
  spans: readonly TelemetrySpanRecord[],
  serviceName = "hunt-command",
): Record<string, unknown> {
  const otlpSpans = spans.map((span) => {
    const scrubbedAttrs = scrubSecretsValue(span.attributes);
    const attributes = Object.entries(scrubbedAttrs)
      .filter(([, v]) => v !== undefined && v !== null)
      .map(([key, val]) => ({
        key,
        value: toOtlpAttributeValue(val),
      }));

    return {
      traceId: span.traceId,
      spanId: span.spanId,
      ...(span.parentSpanId ? { parentSpanId: span.parentSpanId } : {}),
      name: span.name,
      kind: 1,
      startTimeUnixNano: (BigInt(Math.round(span.startTimeMs)) * 1_000_000n).toString(),
      endTimeUnixNano: (BigInt(Math.round(span.endTimeMs)) * 1_000_000n).toString(),
      attributes,
      status: {
        code: span.status === "error" ? 2 : 1,
      },
    };
  });

  return {
    resourceSpans: [
      {
        resource: {
          attributes: [
            { key: "service.name", value: { stringValue: serviceName } },
          ],
        },
        scopeSpans: [
          {
            scope: { name: "@hunt-command/telemetry", version: "0.2.0" },
            spans: otlpSpans,
          },
        ],
      },
    ],
  };
}

function sendDirectLoopbackHttpPost(
  target: ValidatedOtlpTarget,
  bodyBytes: Buffer,
  timeoutMs: number,
): Promise<number> {
  return new Promise<number>((resolve, reject) => {
    let settled = false;
    const fail = (err: Error) => {
      if (!settled) {
        settled = true;
        reject(err);
      }
    };

    const req = http.request(
      {
        hostname: target.hostname,
        port: target.port,
        path: target.pathname,
        method: "POST",
        agent: false,
        family: target.hostname === "::1" ? 6 : 4,
        headers: {
          Host: `${target.urlHostname}:${target.port}`,
          "Content-Type": "application/json",
          "Content-Length": String(bodyBytes.byteLength),
          Connection: "close",
        },
      },
      (res) => {
        const status = res.statusCode ?? 0;
        res.resume();
        if (status >= 300 && status < 400) {
          req.destroy();
          fail(
            new OtlpExportError(
              "otlp_redirect_rejected",
              `Refusing HTTP ${status} redirect from OTLP loopback endpoint`,
            ),
          );
          return;
        }
        res.on("end", () => {
          if (!settled) {
            if (status >= 200 && status < 300) {
              settled = true;
              resolve(status);
            } else {
              fail(
                new OtlpExportError(
                  "otlp_http_error",
                  `OTLP collector returned HTTP ${status}`,
                ),
              );
            }
          }
        });
      },
    );

    req.setTimeout(timeoutMs, () => {
      req.destroy();
      fail(new OtlpExportError("otlp_timeout", "OTLP loopback export timed out"));
    });

    req.on("socket", (socket) => {
      socket.on("connect", () => {
        const remote = socket.remoteAddress;
        if (remote !== "127.0.0.1" && remote !== "::1") {
          socket.destroy();
          fail(
            new OtlpExportError(
              "otlp_socket_non_loopback",
              `Aborted OTLP socket connected to non-loopback peer '${String(remote)}'`,
            ),
          );
          return;
        }
        req.end(bodyBytes);
      });
    });

    req.on("error", (err) => {
      fail(new OtlpExportError("otlp_transport_error", `OTLP loopback transport failed: ${err.message}`));
    });
  });
}

export async function exportOtlpLoopback(
  options: ExportOtlpLoopbackOptions,
): Promise<ExportOtlpResult> {
  // Always validate endpoint syntax & loopback invariants first so misconfigurations fail immediately.
  const target = validateOtlpLoopbackUrl(options.endpoint, {
    internalBoundPorts: options.internalBoundPorts,
  });

  const isTrulySynthetic =
    options.syntheticOnly === true &&
    (options.dataOrigin === undefined || options.dataOrigin === "synthetic");

  if (!isTrulySynthetic && options.allowLocalOtlpOnWorkData !== true) {
    return {
      exported: false,
      skippedReason: "work_data_otlp_disabled",
      exportedSpanCount: 0,
    };
  }

  if (options.spans.length === 0) {
    return {
      exported: true,
      exportedSpanCount: 0,
      statusCode: 200,
    };
  }

  const payload = buildOtlpTracesPayload(options.spans, options.serviceName);
  const bodyBytes = Buffer.from(JSON.stringify(payload), "utf8");
  const timeoutMs = options.timeoutMs ?? 5_000;

  if (options.fetchImpl) {
    let response: Response;
    try {
      response = await options.fetchImpl(target.url.toString(), {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: bodyBytes,
        redirect: "error",
        proxy: "",
        signal: AbortSignal.timeout(timeoutMs),
      });
    } catch (err) {
      throw new OtlpExportError(
        "otlp_redirect_or_transport_rejected",
        `OTLP fetch rejected (redirect or transport failure): ${err instanceof Error ? err.message : String(err)}`,
      );
    }

    if (response.status >= 300 && response.status < 400) {
      throw new OtlpExportError(
        "otlp_redirect_rejected",
        `Refusing HTTP ${response.status} redirect from OTLP collector`,
      );
    }
    if (!response.ok) {
      throw new OtlpExportError(
        "otlp_http_error",
        `OTLP collector returned HTTP ${response.status}`,
      );
    }

    return {
      exported: true,
      exportedSpanCount: options.spans.length,
      statusCode: response.status,
    };
  }

  const statusCode = await sendDirectLoopbackHttpPost(target, bodyBytes, timeoutMs);
  return {
    exported: true,
    exportedSpanCount: options.spans.length,
    statusCode,
  };
}
