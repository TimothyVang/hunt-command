/**
 * Adapted from omp-desktop/app/src/main/features/browser/ws.ts
 * Copyright (c) omp-desktop contributors (MIT License — see root THIRD-PARTY-NOTICES.md).
 * Minimal server-side WebSocket (RFC 6455) for the loopback Watch CDP endpoint:
 * text and binary messages, fragmentation, ping/pong, masked client frame check, and 1009 size cap.
 */
import { createHash } from "node:crypto";
import type { IncomingMessage } from "node:http";
import type { Duplex } from "node:stream";

const GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

const OP_CONTINUATION = 0x0;
const OP_TEXT = 0x1;
const OP_BINARY = 0x2;
const OP_CLOSE = 0x8;
const OP_PING = 0x9;
const OP_PONG = 0xa;

export function acceptKey(key: string): string {
  return createHash("sha1")
    .update(key + GUID)
    .digest("base64");
}

export function encodeFrame(opcode: number, payload: Buffer): Buffer {
  const length = payload.length;
  let header: Buffer;
  if (length < 126) {
    header = Buffer.from([0x80 | opcode, length]);
  } else if (length < 0x10000) {
    header = Buffer.alloc(4);
    header[0] = 0x80 | opcode;
    header[1] = 126;
    header.writeUInt16BE(length, 2);
  } else {
    header = Buffer.alloc(10);
    header[0] = 0x80 | opcode;
    header[1] = 127;
    header.writeBigUInt64BE(BigInt(length), 2);
  }
  return Buffer.concat([header, payload]);
}

export interface WsOptions {
  maxMessageBytes: number;
}

export class WsConnection {
  readonly #socket: Duplex;
  readonly #maxMessageBytes: number;
  readonly #decoder = new TextDecoder("utf-8", { fatal: true });
  #buffer: Buffer = Buffer.alloc(0);
  #fragments: Buffer[] = [];
  #fragmentBytes = 0;
  #fragmentOpcode = 0;
  #closed = false;
  #onMessage: (text: string) => void = () => {};
  #onClose: () => void = () => {};

  constructor(socket: Duplex, options: WsOptions) {
    this.#socket = socket;
    this.#maxMessageBytes = options.maxMessageBytes;
    socket.on("data", (chunk: Buffer) => this.#onData(chunk));
    socket.on("close", () => this.#finish());
    socket.on("error", () => this.#finish());
    // `http.Server` sockets are half-open (`allowHalfOpen: true`): a client that drops or half-closes
    // without a close frame only delivers `end`, never `close`. Treat it as a disconnect and finish our side.
    socket.on("end", () => {
      this.#finish();
      socket.end();
    });
  }

  get closed(): boolean {
    return this.#closed;
  }

  onMessage(listener: (text: string) => void): void {
    this.#onMessage = listener;
  }

  onClose(listener: () => void): void {
    this.#onClose = listener;
  }

  send(text: string): void {
    if (this.#closed) return;
    this.#socket.write(encodeFrame(OP_TEXT, Buffer.from(text, "utf8")));
  }

  close(code = 1000): void {
    if (this.#closed) return;
    const payload = Buffer.alloc(2);
    payload.writeUInt16BE(code, 0);
    this.#socket.end(encodeFrame(OP_CLOSE, payload));
    this.#finish();
  }

  feed(head: Buffer): void {
    if (head.length > 0) this.#onData(head);
  }

  #finish(): void {
    if (this.#closed) return;
    this.#closed = true;
    this.#buffer = Buffer.alloc(0);
    this.#fragments = [];
    this.#onClose();
  }

  #fail(code: number): void {
    this.close(code);
  }

  #onData(chunk: Buffer): void {
    if (this.#closed) return;
    this.#buffer = this.#buffer.length === 0 ? chunk : Buffer.concat([this.#buffer, chunk]);
    while (!this.#closed) {
      const consumed = this.#parseFrame();
      if (consumed === 0) return;
      this.#buffer = this.#buffer.subarray(consumed);
    }
  }

  #parseFrame(): number {
    const buf = this.#buffer;
    if (buf.length < 2) return 0;
    const b0 = buf[0] ?? 0;
    const b1 = buf[1] ?? 0;
    const fin = (b0 & 0x80) !== 0;
    const opcode = b0 & 0x0f;
    if ((b0 & 0x70) !== 0 || (b1 & 0x80) === 0) {
      this.#fail(1002);
      return 0;
    }
    let length = b1 & 0x7f;
    let offset = 2;
    if (length === 126) {
      if (buf.length < 4) return 0;
      length = buf.readUInt16BE(2);
      offset = 4;
    } else if (length === 127) {
      if (buf.length < 10) return 0;
      const big = buf.readBigUInt64BE(2);
      if (big > BigInt(this.#maxMessageBytes)) {
        this.#fail(1009);
        return 0;
      }
      length = Number(big);
      offset = 10;
    }
    const isControl = (opcode & 0x8) !== 0;
    if (isControl && (!fin || length > 125)) {
      this.#fail(1002);
      return 0;
    }
    if (!isControl && this.#fragmentBytes + length > this.#maxMessageBytes) {
      this.#fail(1009);
      return 0;
    }
    if (buf.length < offset + 4 + length) return 0;
    const mask = buf.subarray(offset, offset + 4);
    const payload = Buffer.from(buf.subarray(offset + 4, offset + 4 + length));
    for (let i = 0; i < payload.length; i++) {
      payload[i] = (payload[i] ?? 0) ^ (mask[i & 3] ?? 0);
    }
    this.#onFrame(fin, opcode, payload);
    return offset + 4 + length;
  }

  #onFrame(fin: boolean, opcode: number, payload: Buffer): void {
    switch (opcode) {
      case OP_PING:
        this.#socket.write(encodeFrame(OP_PONG, payload));
        return;
      case OP_PONG:
        return;
      case OP_CLOSE:
        this.close(1000);
        return;
      case OP_TEXT:
      case OP_BINARY:
        if (this.#fragments.length > 0) {
          this.#fail(1002);
          return;
        }
        this.#fragmentOpcode = opcode;
        break;
      case OP_CONTINUATION:
        if (this.#fragments.length === 0) {
          this.#fail(1002);
          return;
        }
        break;
      default:
        this.#fail(1002);
        return;
    }
    this.#fragments.push(payload);
    this.#fragmentBytes += payload.length;
    if (!fin) return;
    const message =
      this.#fragments.length === 1 ? (this.#fragments[0] ?? Buffer.alloc(0)) : Buffer.concat(this.#fragments);
    this.#fragments = [];
    this.#fragmentBytes = 0;
    let text: string;
    try {
      text = this.#decoder.decode(message);
    } catch {
      this.#fail(this.#fragmentOpcode === OP_TEXT ? 1007 : 1003);
      return;
    }
    this.#onMessage(text);
  }
}

/**
 * Completes the RFC 6455 handshake. The returned connection has NOT consumed `head` yet: wire
 * `onMessage`/`onClose` first, then call `feed(head)`, so a frame pipelined with the upgrade request
 * reaches the real listener (and a bad pipelined frame's close reaches the real `onClose`).
 */
export function acceptUpgrade(
  req: IncomingMessage,
  socket: Duplex,
  options: WsOptions,
): WsConnection | null {
  const key = req.headers["sec-websocket-key"];
  const upgrade = req.headers.upgrade;
  const connection = req.headers.connection;
  const valid =
    req.method === "GET" &&
    typeof upgrade === "string" &&
    upgrade.toLowerCase() === "websocket" &&
    typeof connection === "string" &&
    connection
      .toLowerCase()
      .split(",")
      .some((part) => part.trim() === "upgrade") &&
    req.headers["sec-websocket-version"] === "13" &&
    typeof key === "string" &&
    Buffer.from(key, "base64").length === 16;
  if (!valid) {
    rejectUpgrade(socket, 400, "Bad Request");
    return null;
  }
  socket.write(
    "HTTP/1.1 101 Switching Protocols\r\n" +
      "Upgrade: websocket\r\n" +
      "Connection: Upgrade\r\n" +
      `Sec-WebSocket-Accept: ${acceptKey(key)}\r\n\r\n`,
  );
  return new WsConnection(socket, options);
}

export function rejectUpgrade(socket: Duplex, status: number, text: string): void {
  socket.end(`HTTP/1.1 ${status} ${text}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n`);
}
