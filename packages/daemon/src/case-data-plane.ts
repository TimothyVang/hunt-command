import fs from "node:fs";
import path from "node:path";
import {
  assertRoleOwnsTool,
  type CaseMetadata,
  type DataPlaneToolName,
} from "@hunt-command/shared";
import {
  EmbeddedHuntDataPlane,
  dispatchDataPlaneTool,
  throwDataPlaneError,
  type HuntDataPlane,
} from "@hunt-command/data-plane";
import type {
  CaseCapabilities,
  CitationVerificationReceipt,
  CitationVerificationRequest,
  HuntDataPlanePort,
  RoleCapabilityToken,
} from "./ports.ts";
import type { DataPlaneResolver } from "./wave-engine.ts";

const CASE_ID_RE = /^[a-z0-9-]{3,64}$/;

/**
 * Adapts a case `HuntDataPlane` (from `@hunt-command/data-plane`) to the daemon's
 * `HuntDataPlanePort`. The daemon authorizes each call with its own role capability before
 * `executeTool` runs; this adapter re-checks Watch page tools against the same role.
 */
export class CaseDataPlanePort implements HuntDataPlanePort {
  public readonly caseMetadata: CaseMetadata;
  readonly #dataPlane: HuntDataPlane;

  constructor(dataPlane: HuntDataPlane, caseMetadata: CaseMetadata) {
    if (caseMetadata.case_id !== dataPlane.caseId) {
      throw new Error(
        `Case metadata '${caseMetadata.case_id}' does not describe data plane '${dataPlane.caseId}'`,
      );
    }
    this.#dataPlane = dataPlane;
    this.caseMetadata = caseMetadata;
  }

  public async capabilities(): Promise<CaseCapabilities> {
    const all = await this.#dataPlane.elasticSearch({ q: "", size: 1 });
    return {
      hasNetworkCapture: this.#dataPlane.hasNetworkCapture,
      hasIntelSource: this.#dataPlane.hasIntelFeed,
      eventCount: all.total,
      sources: this.caseMetadata.sources,
    };
  }

  public async executeTool(
    capabilityToken: RoleCapabilityToken,
    toolName: DataPlaneToolName,
    params: Record<string, unknown>,
    signal?: AbortSignal,
  ): Promise<unknown> {
    signal?.throwIfAborted();
    return dispatchDataPlaneTool(this.#dataPlane, toolName, params, (pageTool) => {
      assertRoleOwnsTool(capabilityToken.profile, pageTool, capabilityToken.stepId);
    });
  }

  public async verifyCitations(
    request: CitationVerificationRequest,
    signal?: AbortSignal,
  ): Promise<CitationVerificationReceipt> {
    signal?.throwIfAborted();
    const checkedAt = new Date().toISOString();
    const requested = [...request.event_ids, ...request.frame_ids, ...request.ioc_ids];
    const base = {
      checked_at: checkedAt,
      case_id: request.case_id,
      total_checked: new Set(requested).size,
      ambiguous_ids: [] as string[],
    };

    if (request.case_id !== this.#dataPlane.caseId) {
      return {
        ...base,
        verified: false,
        missing_event_ids: [],
        missing_frame_ids: [],
        missing_ioc_ids: [],
        out_of_scope_ids: [...new Set(requested)].sort(),
        source_status: "ok",
        diagnostic: `Citations name case '${request.case_id}', not '${this.#dataPlane.caseId}'`,
      };
    }

    let result: Awaited<ReturnType<HuntDataPlane["verifyCitations"]>>;
    try {
      result = await this.#dataPlane.verifyCitations(requested);
    } catch (err) {
      return {
        ...base,
        verified: false,
        missing_event_ids: [],
        missing_frame_ids: [],
        missing_ioc_ids: [],
        out_of_scope_ids: [],
        source_status: "unavailable",
        diagnostic: `Citation backend failed: ${err instanceof Error ? err.message : String(err)}`,
      };
    }

    const failed = new Set([...result.unresolved, ...result.malformed]);
    const missing = (ids: readonly string[]) => [...new Set(ids.filter((id) => failed.has(id)))];
    return {
      ...base,
      verified: result.allValid,
      missing_event_ids: missing(request.event_ids),
      missing_frame_ids: missing(request.frame_ids),
      missing_ioc_ids: missing(request.ioc_ids),
      out_of_scope_ids: [],
      source_status: "ok",
    };
  }

  public async close(): Promise<void> {
    await this.#dataPlane.close();
  }
}

export interface CaseDirDataPlaneResolverOptions {
  /** Directory holding one `<caseId>/case.json` case pack per case. */
  readonly casesDir: string;
  /** Where the embedded data plane keeps its per-case SQLite index. */
  readonly cacheDir: string;
}

export interface CaseDirDataPlaneResolver {
  readonly resolve: DataPlaneResolver;
  /** Closes every case data plane this resolver opened. */
  close(): Promise<void>;
}

/**
 * The default `serve` data plane: opens `<casesDir>/<caseId>` with `EmbeddedHuntDataPlane`
 * once per case and shares that read-only plane across runs of the same case.
 */
export function createCaseDirDataPlaneResolver(
  options: CaseDirDataPlaneResolverOptions,
): CaseDirDataPlaneResolver {
  const casesDir = path.resolve(options.casesDir);
  const open = new Map<string, Promise<CaseDataPlanePort>>();

  const resolve: DataPlaneResolver = (caseId) => {
    if (!CASE_ID_RE.test(caseId)) {
      throwDataPlaneError(400, "explicit_case_id_required", `Invalid case_id '${caseId}'`);
    }
    let port = open.get(caseId);
    if (!port) {
      const caseDir = path.join(casesDir, caseId);
      if (!fs.existsSync(path.join(caseDir, "case.json"))) {
        throwDataPlaneError(404, "not_found", `No case pack at '${caseDir}'`);
      }
      port = EmbeddedHuntDataPlane.open(caseDir, { cacheDir: options.cacheDir }).then(
        (dataPlane) => new CaseDataPlanePort(dataPlane, dataPlane.describeCase()),
      );
      open.set(caseId, port);
      port.catch(() => open.delete(caseId));
    }
    return port;
  };

  return {
    resolve,
    async close() {
      const ports = [...open.values()];
      open.clear();
      await Promise.allSettled(ports.map(async (p) => (await p).close()));
    },
  };
}
