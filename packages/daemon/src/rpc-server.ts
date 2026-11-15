import { StringDecoder } from "node:string_decoder";
import {
  DataPlaneAccessError,
  RpcEventNotificationSchema,
  RpcRequestSchema,
  RpcResponseSchema,
  type RpcEventNotification,
  type RpcRequest,
  type RpcResponse,
} from "@hunt-command/shared";
import { executeDriveGates, type DriveGatesCommandInput } from "./drive-gates.ts";
import { GateDecisionError } from "./gates.ts";
import type { DaemonTelemetryEvent, HuntDataPlanePort } from "./ports.ts";
import type { HuntWaveEngine } from "./wave-engine.ts";

export const DEFAULT_MAX_NDJSON_LINE_BYTES = 1_048_576; // 1 MiB

/**
 * Bounded streaming NDJSON splitter (`LineSplitter`):
 * Safely decodes chunked UTF-8 buffers across arbitrary chunk boundaries, splits on `\r?\n`,
 * and fails closed if any single unterminated line exceeds `maxLineBytes`.
 */
export class LineSplitter {
  private readonly maxLineBytes: number;
  private readonly decoder = new StringDecoder("utf8");
  private buffer = "";

  constructor(maxLineBytes = DEFAULT_MAX_NDJSON_LINE_BYTES) {
    if (!Number.isInteger(maxLineBytes) || maxLineBytes <= 0) {
      throw new RangeError("maxLineBytes must be a positive integer");
    }
    this.maxLineBytes = maxLineBytes;
  }

  public push(chunk: Uint8Array | Buffer | string): string[] {
    const piece = typeof chunk === "string" ? chunk : this.decoder.write(Buffer.from(chunk));
    this.buffer += piece;

    const lines: string[] = [];
    let newlineIdx = this.buffer.indexOf("\n");
    while (newlineIdx !== -1) {
      const rawLine = this.buffer.slice(0, newlineIdx).replace(/\r$/, "");
      this.buffer = this.buffer.slice(newlineIdx + 1);
      if (Buffer.byteLength(rawLine, "utf8") > this.maxLineBytes) {
        throw new Error(`NDJSON line exceeds maxLineBytes (${this.maxLineBytes} bytes)`);
      }
      if (rawLine.trim().length > 0) {
        lines.push(rawLine);
      }
      newlineIdx = this.buffer.indexOf("\n");
    }

    if (Buffer.byteLength(this.buffer, "utf8") > this.maxLineBytes) {
      this.buffer = "";
      throw new Error(`Unterminated NDJSON line exceeds maxLineBytes (${this.maxLineBytes} bytes)`);
    }

    return lines;
  }

  public flush(): string[] {
    const tail = (this.buffer + this.decoder.end()).replace(/\r$/, "");
    this.buffer = "";
    if (!tail.trim()) {
      return [];
    }
    if (Buffer.byteLength(tail, "utf8") > this.maxLineBytes) {
      throw new Error(`NDJSON trailing line exceeds maxLineBytes (${this.maxLineBytes} bytes)`);
    }
    return [tail];
  }
}

export interface HuntDaemonRpcServerOptions {
  readonly engine: HuntWaveEngine;
  readonly resolveDataPlane?: (caseId: string) => Promise<HuntDataPlanePort> | HuntDataPlanePort;
  readonly writeLine: (ndjsonLine: string) => void;
}

/**
 * Persistent `hunt-daemon` stdio NDJSON JSON-RPC 2.0 server:
 * Validates every inbound frame with `RpcRequestSchema` and every outbound frame
 * with `RpcResponseSchema` / `RpcEventNotificationSchema`.
 */
export class HuntDaemonRpcServer {
  private readonly engine: HuntWaveEngine;
  private readonly resolveDataPlane?: (
    caseId: string,
  ) => Promise<HuntDataPlanePort> | HuntDataPlanePort;
  private readonly writeLine: (ndjsonLine: string) => void;
  private readonly splitter: LineSplitter;

  constructor(options: HuntDaemonRpcServerOptions, maxLineBytes = DEFAULT_MAX_NDJSON_LINE_BYTES) {
    this.engine = options.engine;
    this.resolveDataPlane = options.resolveDataPlane ?? options.engine.resolveDataPlane;
    this.writeLine = options.writeLine;
    this.splitter = new LineSplitter(maxLineBytes);
  }

  public emitTelemetryEvent(ev: DaemonTelemetryEvent): void {
    const notification: RpcEventNotification = RpcEventNotificationSchema.parse({
      jsonrpc: "2.0",
      method: "hunt.event",
      params: {
        hunt_id: ev.runId,
        seq: ev.seq,
        ts: ev.ts,
        type: ev.type,
        payload: ev.payload,
      },
    });
    this.writeLine(`${JSON.stringify(notification)}\n`);
  }

  public async handleChunk(chunk: Uint8Array | Buffer | string): Promise<void> {
    let lines: string[];
    try {
      lines = this.splitter.push(chunk);
    } catch (err) {
      const errResp: RpcResponse = RpcResponseSchema.parse({
        jsonrpc: "2.0",
        id: "frame-error",
        error: {
          code: -32700,
          message: err instanceof Error ? err.message : String(err),
          error_code: "ndjson_frame_overflow",
        },
      });
      this.writeLine(`${JSON.stringify(errResp)}\n`);
      return;
    }

    for (const line of lines) {
      await this.handleLine(line);
    }
  }

  public async handleLine(line: string): Promise<RpcResponse> {
    let rawJson: unknown;
    try {
      rawJson = JSON.parse(line);
    } catch (err) {
      const resp = RpcResponseSchema.parse({
        jsonrpc: "2.0",
        id: "parse-error",
        error: {
          code: -32700,
          message: `Invalid JSON: ${err instanceof Error ? err.message : String(err)}`,
          error_code: "parse_error",
        },
      });
      this.writeLine(`${JSON.stringify(resp)}\n`);
      return resp;
    }

    const parsedReq = RpcRequestSchema.safeParse(rawJson);
    if (!parsedReq.success) {
      const rawId =
        rawJson && typeof rawJson === "object" && "id" in rawJson &&
        (typeof (rawJson as { id?: unknown }).id === "string" ||
          typeof (rawJson as { id?: unknown }).id === "number")
          ? ((rawJson as { id: string | number }).id)
          : "invalid-request";
      const resp = RpcResponseSchema.parse({
        jsonrpc: "2.0",
        id: rawId,
        error: {
          code: -32600,
          message: parsedReq.error.issues[0]?.message ?? "Invalid JSON-RPC 2.0 request",
          error_code: "invalid_request",
        },
      });
      this.writeLine(`${JSON.stringify(resp)}\n`);
      return resp;
    }

    const req = parsedReq.data;
    const response = await this.dispatchRequest(req);
    const validated = RpcResponseSchema.parse(response);
    this.writeLine(`${JSON.stringify(validated)}\n`);
    return validated;
  }

  private async dispatchRequest(req: RpcRequest): Promise<RpcResponse> {
    const params = req.params ?? {};

    try {
      switch (req.method) {
        case "daemon.ping": {
          return {
            jsonrpc: "2.0",
            id: req.id,
            result: {
              ok: true,
              service: "hunt-daemon",
              active_hunts: this.engine.getActiveHuntCount(),
              max_concurrent_hunts: this.engine.maxConcurrentHunts,
            },
          };
        }

        case "hunt.start": {
          const caseId = typeof params.case_id === "string" ? params.case_id : "";
          const scopeText = typeof params.scope === "string" ? params.scope : "";
          if (!caseId || !scopeText) {
            throw new Error("hunt.start requires non-empty 'case_id' and 'scope'");
          }
          if (!this.resolveDataPlane) {
            throw new Error("No resolveDataPlane factory configured on HuntDaemonRpcServer");
          }
          const dataPlane = await this.resolveDataPlane(caseId);
          const run = await this.engine.startHunt({
            runId: typeof params.run_id === "string" ? params.run_id : undefined,
            scopeText,
            dataPlane,
            followUps: typeof params.follow_ups === "number" ? params.follow_ups : undefined,
            maxTotalTokens:
              typeof params.max_total_tokens === "number" ? params.max_total_tokens : undefined,
            stageGuidance:
              params.stage_guidance && typeof params.stage_guidance === "object"
                ? (params.stage_guidance as Partial<Record<string, string>>)
                : undefined,
          });
          return { jsonrpc: "2.0", id: req.id, result: run };
        }

        case "hunt.status": {
          const runId = typeof params.run_id === "string" ? params.run_id : "";
          const run = this.engine.stateStore.getRun(runId);
          if (!run) {
            return {
              jsonrpc: "2.0",
              id: req.id,
              error: {
                code: -32004,
                message: `Unknown hunt '${runId}'`,
                error_code: "hunt_not_found",
              },
            };
          }
          return { jsonrpc: "2.0", id: req.id, result: run };
        }

        case "hunt.list": {
          const runs = this.engine.stateStore.listRuns();
          return { jsonrpc: "2.0", id: req.id, result: { runs } };
        }

        case "hunt.cancel": {
          const runId = typeof params.run_id === "string" ? params.run_id : "";
          const reason = typeof params.reason === "string" ? params.reason : "global_stop";
          const cancelled = this.engine.cancelRun(runId, reason);
          return { jsonrpc: "2.0", id: req.id, result: cancelled };
        }

        case "hunt.decideGate": {
          if (params.via === "slack") {
            throw new GateDecisionError(
              "automated_channel_forbidden",
              "via='slack' is reserved for the in-process Slack bridge and is not accepted over RPC",
            );
          }
          const updated = await this.engine.submitGateDecision({
            decisionId: typeof params.decision_id === "string" ? params.decision_id : undefined,
            huntId: String(params.hunt_id ?? ""),
            gate: String(params.gate ?? ""),
            action: params.action === "reject" ? "reject" : "approve",
            // `slack` is reserved for the in-process Slack bridge and is never accepted over RPC;
            // principal/RBAC role come only from the verified `operator_token`.
            via: params.via === "desktop" || params.via === "automated" ? params.via : "cli",
            operatorToken:
              typeof params.operator_token === "string" ? params.operator_token : undefined,
            payloadSha256: String(params.payload_sha256 ?? ""),
            checkNote: typeof params.check_note === "string" ? params.check_note : undefined,
          });
          return { jsonrpc: "2.0", id: req.id, result: updated };
        }

        case "hunt.recover": {
          if (this.engine.getActiveHuntCount() > 0) {
            throw new Error(
              "recover_refused_active_hunts: hunt.recover is rejected while hunts are actively executing",
            );
          }
          const recovered = this.engine.recoverInFlightRunsOnStartup();
          return {
            jsonrpc: "2.0",
            id: req.id,
            result: { recovered_count: recovered.length, runs: recovered },
          };
        }

        case "hunt.resume": {
          const runId = typeof params.run_id === "string" ? params.run_id : "";
          const run = this.engine.stateStore.getRun(runId);
          if (!run) {
            throw new Error(`Unknown hunt '${runId}'`);
          }
          if (!this.resolveDataPlane) {
            throw new Error("No resolveDataPlane factory configured on HuntDaemonRpcServer");
          }
          const dataPlane = await this.resolveDataPlane(run.case_id);
          const resumed = await this.engine.resumeParkedRun(runId, dataPlane);
          return { jsonrpc: "2.0", id: req.id, result: resumed };
        }

        case "driveGates.run": {
          const result = await executeDriveGates(
            this.engine,
            params as unknown as DriveGatesCommandInput,
          );
          return { jsonrpc: "2.0", id: req.id, result };
        }

        default: {
          return {
            jsonrpc: "2.0",
            id: req.id,
            error: {
              code: -32601,
              message: `Unknown RPC method '${req.method}'`,
              error_code: "method_not_found",
            },
          };
        }
      }
    } catch (err) {
      const errorCode =
        err instanceof GateDecisionError
          ? err.errorCode
          : err instanceof DataPlaneAccessError
            ? err.errorCode
            : "rpc_execution_error";
      return {
        jsonrpc: "2.0",
        id: req.id,
        error: {
          code: -32000,
          message: err instanceof Error ? err.message : String(err),
          error_code: errorCode,
        },
      };
    }
  }
}
