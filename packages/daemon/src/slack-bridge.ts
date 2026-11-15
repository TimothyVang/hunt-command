import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { FORBIDDEN_SUBSCRIPTION_ENV_KEYS } from "./hunter-policy.ts";
import { GateDecisionError, MAX_CHECK_NOTE_CHARS, type RbacRole, type SubmitGateDecisionInput } from "./gates.ts";
import type { PendingGateReviewEnvelope } from "./gates.ts";

const SLACK_USER_ID_RE = /^[UW][A-Z0-9]{2,20}$/;
const SLACK_CHANNEL_ID_RE = /^[CDG][A-Z0-9]{2,20}$/;
const NONCE_32_HEX_RE = /^[0-9a-f]{32}$/i;

const BOT_TOKEN_PREFIX = `xoxb${"-"}`;
const APP_TOKEN_PREFIX = `xapp${"-"}`;

export const SLACK_BRIDGE_STRIPPED_ENV_KEYS = [
  "SLACK_BOT_TOKEN",
  "SLACK_APP_TOKEN",
  "SLACK_SIGNING_SECRET",
  "SLACK_WEBHOOK_URL",
  ...FORBIDDEN_SUBSCRIPTION_ENV_KEYS,
] as const;

/**
 * Strips `SLACK_BOT_TOKEN`, `SLACK_APP_TOKEN`, and all paid API keys from any bot/child environment
 * (`ADR 0004`: bot/hunter processes NEVER hold Slack tokens).
 */
export function buildBotSanitizedEnv(
  sourceEnv: Readonly<Record<string, string | undefined>> = process.env,
): Record<string, string> {
  const strippedSet = new Set<string>(SLACK_BRIDGE_STRIPPED_ENV_KEYS);
  const out: Record<string, string> = {};
  for (const [key, value] of Object.entries(sourceEnv)) {
    if (value === undefined) continue;
    if (strippedSet.has(key) || key.toUpperCase().startsWith("SLACK_")) {
      continue;
    }
    out[key] = value;
  }
  return out;
}

/**
 * Constant-time comparison of 32-hex (128-bit) Slack action/modal nonces.
 */
export function verifyActionNonceConstantTime(expectedHex: string, candidateHex: string): boolean {
  if (!NONCE_32_HEX_RE.test(expectedHex) || !NONCE_32_HEX_RE.test(candidateHex)) {
    return false;
  }
  const expectedBuf = Buffer.from(expectedHex.toLowerCase(), "hex");
  const candidateBuf = Buffer.from(candidateHex.toLowerCase(), "hex");
  if (expectedBuf.byteLength !== 16 || candidateBuf.byteLength !== 16) {
    return false;
  }
  return crypto.timingSafeEqual(expectedBuf, candidateBuf);
}

export interface SlackApiTransport {
  openSocketUrl(): Promise<string>;
  postMessage(params: {
    channel: string;
    text: string;
    blocks: Record<string, unknown>[];
  }): Promise<{ ts: string; channel: string }>;
  openModal(params: {
    trigger_id: string;
    view: Record<string, unknown>;
  }): Promise<void>;
  updateMessage(params: {
    channel: string;
    ts: string;
    text: string;
    blocks?: Record<string, unknown>[];
  }): Promise<void>;
}

export class HttpSlackApiTransport implements SlackApiTransport {
  private readonly botToken: string;
  private readonly appToken: string;
  private readonly fetchImpl: typeof fetch;

  constructor(options: { botToken: string; appToken: string; fetchImpl?: typeof fetch }) {
    if (!options.botToken.startsWith(BOT_TOKEN_PREFIX)) {
      throw new Error("SLACK_BOT_TOKEN must be a valid bot token");
    }
    if (!options.appToken.startsWith(APP_TOKEN_PREFIX)) {
      throw new Error("SLACK_APP_TOKEN must be a valid Socket Mode app-level token");
    }
    this.botToken = options.botToken;
    this.appToken = options.appToken;
    this.fetchImpl = options.fetchImpl ?? globalThis.fetch;
  }

  public async openSocketUrl(): Promise<string> {
    const res = await this.fetchImpl("https://slack.com/api/apps.connections.open", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${this.appToken}`,
        "Content-Type": "application/x-www-form-urlencoded",
      },
    });
    const data = (await res.json()) as { ok?: boolean; url?: string; error?: string };
    if (!data.ok || typeof data.url !== "string" || !data.url.startsWith("wss://")) {
      throw new Error(`Slack apps.connections.open failed: ${data.error ?? "missing wss url"}`);
    }
    return data.url;
  }

  public async postMessage(params: {
    channel: string;
    text: string;
    blocks: Record<string, unknown>[];
  }): Promise<{ ts: string; channel: string }> {
    const res = await this.fetchImpl("https://slack.com/api/chat.postMessage", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${this.botToken}`,
        "Content-Type": "application/json; charset=utf-8",
      },
      body: JSON.stringify(params),
    });
    const data = (await res.json()) as {
      ok?: boolean;
      ts?: string;
      channel?: string;
      error?: string;
    };
    if (!data.ok || !data.ts) {
      throw new Error(`Slack chat.postMessage failed: ${data.error ?? "unknown error"}`);
    }
    return { ts: data.ts, channel: data.channel ?? params.channel };
  }

  public async openModal(params: {
    trigger_id: string;
    view: Record<string, unknown>;
  }): Promise<void> {
    const res = await this.fetchImpl("https://slack.com/api/views.open", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${this.botToken}`,
        "Content-Type": "application/json; charset=utf-8",
      },
      body: JSON.stringify(params),
    });
    const data = (await res.json()) as { ok?: boolean; error?: string };
    if (!data.ok) {
      throw new Error(`Slack views.open failed: ${data.error ?? "unknown error"}`);
    }
  }

  public async updateMessage(params: {
    channel: string;
    ts: string;
    text: string;
    blocks?: Record<string, unknown>[];
  }): Promise<void> {
    const res = await this.fetchImpl("https://slack.com/api/chat.update", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${this.botToken}`,
        "Content-Type": "application/json; charset=utf-8",
      },
      body: JSON.stringify(params),
    });
    const data = (await res.json()) as { ok?: boolean; error?: string };
    if (!data.ok) {
      throw new Error(`Slack chat.update failed: ${data.error ?? "unknown error"}`);
    }
  }
}

export interface SlackBridgeOptions {
  readonly pendingDir: string;
  readonly claimedDir: string;
  readonly channelId: string;
  readonly allowedUserIds: readonly string[];
  readonly userRoles?: Readonly<Record<string, RbacRole>>;
  readonly transport: SlackApiTransport;
  readonly onGateDecision: (decision: SubmitGateDecisionInput) => Promise<unknown>;
}

interface TrackedSlackGatePost {
  readonly envelope: PendingGateReviewEnvelope;
  readonly claimedFilePath: string;
  readonly channel: string;
  readonly messageTs: string;
}

interface ButtonActionMetadata {
  readonly hunt_uuid: string;
  readonly gate: string;
  readonly action: "approve" | "reject";
  readonly nonce: string;
  readonly payload_sha256: string;
  readonly synthetic_only: boolean;
}

export const NON_SYNTHETIC_MODAL_WARNING_TEXT =
  ":rotating_light: *RED NON-SYNTHETIC TELEMETRY WARNING* — Real unclassified/dataset telemetry hunt (`synthetic_only=false`). Do NOT paste raw hostnames, usernames, IPs, paths, or log lines into your check note.";

/**
 * Outbound-only Slack Socket Mode human-gate bridge (`ADR 0004` + Rule 4 `EgressGuard`):
 * - Recovers `claimed/*.json` -> `pending/*.json` on bridge restart
 * - Enforces allowlisted `SLACK_USER_ID` (`[UW][A-Z0-9]{2,20}`)
 * - Enforces constant-time `crypto.timingSafeEqual` 32-hex nonce verification
 * - Uses 2-step Block Kit card -> `"What did you check?"` modal (`1..1000` chars) with red non-synthetic warning
 * - Never sends non-synthetic case content, claims, or hostnames onto Slack (`StrictEgressGuard` card only!)
 */
export class SlackSocketModeBridge {
  private readonly pendingDir: string;
  private readonly claimedDir: string;
  private readonly channelId: string;
  private readonly allowedUsers: ReadonlySet<string>;
  private readonly userRoles: Readonly<Record<string, RbacRole>>;
  private readonly transport: SlackApiTransport;
  private readonly onGateDecision: (decision: SubmitGateDecisionInput) => Promise<unknown>;
  private readonly activePosts = new Map<string, TrackedSlackGatePost>();

  constructor(options: SlackBridgeOptions) {
    if (!SLACK_CHANNEL_ID_RE.test(options.channelId)) {
      throw new Error(`Invalid Slack channel ID '${options.channelId}'`);
    }
    if (options.allowedUserIds.length === 0) {
      throw new Error("SlackSocketModeBridge requires >= 1 allowlisted SLACK_USER_ID");
    }
    for (const uid of options.allowedUserIds) {
      if (!SLACK_USER_ID_RE.test(uid)) {
        throw new Error(`Invalid allowlisted SLACK_USER_ID '${uid}'`);
      }
    }
    this.pendingDir = path.resolve(options.pendingDir);
    this.claimedDir = path.resolve(options.claimedDir);
    this.channelId = options.channelId;
    this.allowedUsers = new Set(options.allowedUserIds);
    this.userRoles = options.userRoles ?? {};
    this.transport = options.transport;
    this.onGateDecision = options.onGateDecision;

    fs.mkdirSync(this.pendingDir, { recursive: true });
    fs.mkdirSync(this.claimedDir, { recursive: true });
  }

  private postKey(huntId: string, gate: string): string {
    return `${huntId}::${gate}`;
  }

  /**
   * Moves any orphaned `claimed/*__review.json` files back to `pending/` on restart
   * so crashes before operator completion never strand a gate notification.
   */
  public recoverClaimedToPending(): number {
    let recovered = 0;
    const entries = fs.readdirSync(this.claimedDir);
    for (const name of entries) {
      if (!name.endsWith("__review.json")) continue;
      const src = path.join(this.claimedDir, name);
      const dst = path.join(this.pendingDir, name);
      if (!fs.existsSync(dst)) {
        fs.renameSync(src, dst);
        recovered += 1;
      } else {
        fs.unlinkSync(src);
      }
    }
    return recovered;
  }

  public buildGateCardBlocks(envelope: PendingGateReviewEnvelope): Record<string, unknown>[] {
    const { card } = envelope;
    const fieldsLines = [
      `*Hunt UUID:* \`${card.hunt_uuid}\``,
      `*Wave:* \`${card.wave}\``,
      `*Gate:* \`${card.gate_kind}\``,
      `*Status:* \`${card.status_enum}\``,
      `*Opened (UTC):* \`${card.opened_at_utc}\``,
      `*Digest:* \`${card.payload_sha256.slice(0, 16)}…\``,
    ];
    if (card.reason_code) {
      fieldsLines.push(`*Reason Code:* \`${card.reason_code}\``);
    }
    if (envelope.synthetic_only && card.synthetic_summary) {
      fieldsLines.push(
        `*Case (Synthetic):* \`${card.synthetic_summary.case_id}\` (${card.synthetic_summary.claim_count ?? 0} claims)`,
      );
    }

    const approveVal: ButtonActionMetadata = {
      hunt_uuid: card.hunt_uuid,
      gate: card.gate_kind,
      action: "approve",
      nonce: envelope.action_nonce,
      payload_sha256: card.payload_sha256,
      synthetic_only: envelope.synthetic_only,
    };
    const rejectVal: ButtonActionMetadata = {
      ...approveVal,
      action: "reject",
    };

    return [
      {
        type: "header",
        text: {
          type: "plain_text",
          text: `Hunt Gate Review: ${card.gate_kind}`,
        },
      },
      {
        type: "section",
        text: {
          type: "mrkdwn",
          text: fieldsLines.join("\n"),
        },
      },
      {
        type: "actions",
        elements: [
          {
            type: "button",
            action_id: "hunt_gate_approve",
            style: "primary",
            text: { type: "plain_text", text: "Approve…" },
            value: JSON.stringify(approveVal),
          },
          {
            type: "button",
            action_id: "hunt_gate_reject",
            style: "danger",
            text: { type: "plain_text", text: "Reject…" },
            value: JSON.stringify(rejectVal),
          },
        ],
      },
    ];
  }

  /**
   * Atomically claims `pending/*__review.json` -> `claimed/*__review.json` and posts
   * the egress-sanitized Block Kit gate card over the outbound Slack Web API.
   */
  public async pollAndPublishPendingReviews(): Promise<number> {
    let published = 0;
    const files = fs.readdirSync(this.pendingDir).filter((f) => f.endsWith("__review.json")).sort();

    for (const name of files) {
      const pendingPath = path.join(this.pendingDir, name);
      const claimedPath = path.join(this.claimedDir, name);
      try {
        fs.renameSync(pendingPath, claimedPath);
      } catch {
        continue;
      }

      try {
        const raw = fs.readFileSync(claimedPath, "utf8");
        const envelope = JSON.parse(raw) as PendingGateReviewEnvelope;
        const blocks = this.buildGateCardBlocks(envelope);
        const posted = await this.transport.postMessage({
          channel: this.channelId,
          text: `Hunt ${envelope.card.hunt_uuid} awaiting '${envelope.card.gate_kind}' human gate decision`,
          blocks,
        });

        this.activePosts.set(this.postKey(envelope.card.hunt_uuid, envelope.card.gate_kind), {
          envelope,
          claimedFilePath: claimedPath,
          channel: posted.channel,
          messageTs: posted.ts,
        });
        published += 1;
      } catch (err) {
        // Restore to pending on transient publish error so next poll retries cleanly
        try {
          if (fs.existsSync(claimedPath) && !fs.existsSync(pendingPath)) {
            fs.renameSync(claimedPath, pendingPath);
          }
        } catch {}
        throw err;
      }
    }

    return published;
  }

  /**
   * Step 1 of 2-step Slack approval flow:
   * Verifies allowlisted `user.id` and constant-time 32-hex `nonce`, then opens the
   * `"What did you check?"` check-note modal (including red warning banner when `!synthetic_only`).
   */
  public async handleBlockAction(payload: {
    user: { id: string };
    trigger_id: string;
    actions: ReadonlyArray<{ action_id: string; value: string }>;
  }): Promise<void> {
    const userId = payload.user?.id ?? "";
    if (!this.allowedUsers.has(userId)) {
      throw new GateDecisionError(
        "rbac_denied",
        `Slack user '${userId}' is not in allowlisted SLACK_USER_IDS`,
      );
    }

    const firstAction = payload.actions[0];
    if (!firstAction) {
      throw new GateDecisionError("invalid_gate_decision", "Missing Slack block action payload");
    }

    let meta: ButtonActionMetadata;
    try {
      meta = JSON.parse(firstAction.value) as ButtonActionMetadata;
    } catch {
      throw new GateDecisionError("invalid_gate_decision", "Malformed Slack button action JSON");
    }

    const tracked = this.activePosts.get(this.postKey(meta.hunt_uuid, meta.gate));
    if (!tracked) {
      throw new GateDecisionError(
        "gate_not_open",
        `No active Slack gate review tracked for ${meta.hunt_uuid} (${meta.gate})`,
      );
    }

    if (!verifyActionNonceConstantTime(tracked.envelope.action_nonce, meta.nonce)) {
      throw new GateDecisionError(
        "invalid_gate_decision",
        "Slack gate action nonce mismatch (constant-time verification failed)",
      );
    }

    const modalBlocks: Record<string, unknown>[] = [];
    if (!tracked.envelope.synthetic_only) {
      modalBlocks.push({
        type: "section",
        text: {
          type: "mrkdwn",
          text: NON_SYNTHETIC_MODAL_WARNING_TEXT,
        },
      });
    }

    modalBlocks.push({
      type: "input",
      block_id: "check_note_block",
      element: {
        type: "plain_text_input",
        action_id: "check_note_input",
        multiline: true,
        min_length: 1,
        max_length: MAX_CHECK_NOTE_CHARS,
        placeholder: {
          type: "plain_text",
          text: "Summarize what you verified in the local desktop/CLI workspace (1..1000 chars)…",
        },
      },
      label: {
        type: "plain_text",
        text: "What did you check?",
      },
    });

    await this.transport.openModal({
      trigger_id: payload.trigger_id,
      view: {
        type: "modal",
        callback_id: "hunt_gate_check_note_modal",
        private_metadata: JSON.stringify(meta),
        title: {
          type: "plain_text",
          text: meta.action === "approve" ? "Approve Hunt Gate" : "Reject Hunt Gate",
        },
        submit: {
          type: "plain_text",
          text: meta.action === "approve" ? "Confirm Approve" : "Confirm Reject",
        },
        close: {
          type: "plain_text",
          text: "Cancel",
        },
        blocks: modalBlocks,
      },
    });
  }

  /**
   * Step 2 of 2-step Slack approval flow:
   * Verifies allowlisted `user.id`, constant-time 32-hex `nonce`, and `1..1000` char `check_note`,
   * then submits the authenticated human gate decision (`via: "slack"`).
   */
  public async handleViewSubmission(payload: {
    user: { id: string };
    view: {
      callback_id: string;
      private_metadata: string;
      state: {
        values: Record<string, Record<string, { value?: string | null }>>;
      };
    };
  }): Promise<void> {
    const userId = payload.user?.id ?? "";
    if (!this.allowedUsers.has(userId)) {
      throw new GateDecisionError(
        "rbac_denied",
        `Slack user '${userId}' is not in allowlisted SLACK_USER_IDS`,
      );
    }

    let meta: ButtonActionMetadata;
    try {
      meta = JSON.parse(payload.view.private_metadata) as ButtonActionMetadata;
    } catch {
      throw new GateDecisionError("invalid_gate_decision", "Malformed Slack modal private_metadata");
    }

    const key = this.postKey(meta.hunt_uuid, meta.gate);
    const tracked = this.activePosts.get(key);
    if (!tracked) {
      throw new GateDecisionError(
        "gate_not_open",
        `Gate '${meta.gate}' for hunt '${meta.hunt_uuid}' is no longer open`,
      );
    }

    if (!verifyActionNonceConstantTime(tracked.envelope.action_nonce, meta.nonce)) {
      throw new GateDecisionError(
        "invalid_gate_decision",
        "Slack modal nonce mismatch (constant-time verification failed)",
      );
    }

    const rawNote =
      payload.view.state?.values?.check_note_block?.check_note_input?.value ?? "";
    const trimmedNote = rawNote.trim();
    if (trimmedNote.length < 1) {
      throw new GateDecisionError("check_note_required", "Slack check_note must be 1..1000 chars");
    }
    if (trimmedNote.length > MAX_CHECK_NOTE_CHARS) {
      throw new GateDecisionError("check_note_too_long", "Slack check_note exceeds 1000 chars");
    }

    const rbacRole: RbacRole = this.userRoles[userId] ?? "analyst";

    await this.onGateDecision({
      decisionId: `slack-${meta.hunt_uuid}-${meta.gate}-${meta.nonce.slice(0, 12)}`,
      huntId: meta.hunt_uuid,
      gate: meta.gate,
      action: meta.action,
      via: "slack",
      authenticatedPrincipal: `slack:${userId}`,
      rbacRole,
      payloadSha256: meta.payload_sha256,
      checkNote: trimmedNote,
    });

    this.activePosts.delete(key);
    try {
      if (fs.existsSync(tracked.claimedFilePath)) {
        fs.unlinkSync(tracked.claimedFilePath);
      }
    } catch {}

    await this.transport.updateMessage({
      channel: tracked.channel,
      ts: tracked.messageTs,
      text: `Gate '${meta.gate}' ${meta.action === "approve" ? "APPROVED" : "REJECTED"} by <@${userId}>`,
    });
  }
}
